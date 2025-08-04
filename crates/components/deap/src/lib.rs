//! Dual-execution with Asymmetric Privacy (DEAP) protocol.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

mod map;

use std::{mem, sync::Arc};

use async_trait::async_trait;
use mpz_common::Context;
use mpz_core::bitvec::BitVec;
use mpz_vm_core::{
    memory::{binary::Binary, DecodeFuture, Memory, Repr, Slice, View},
    Call, Callable, Execute, Vm, VmError,
};
use rangeset::{Difference, RangeSet, UnionMut};
use tokio::sync::{Mutex, MutexGuard, OwnedMutexGuard};

type Error = DeapError;

/// The role of the DEAP VM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum Role {
    Leader,
    Follower,
}

/// DEAP VM.
#[derive(Debug)]
pub struct Deap<Mpc, Zk> {
    role: Role,
    mpc: Arc<Mutex<Mpc>>,
    zk: Arc<Mutex<Zk>>,
    /// Mapping between the memories of the MPC and ZK VMs.
    memory_map: map::MemoryMap,
    /// Ranges of the follower's private inputs in the MPC VM.
    follower_input_ranges: RangeSet<usize>,
    /// Private inputs of the follower in the MPC VM.
    follower_inputs: Vec<Slice>,
    /// Outputs of the follower from the ZK VM. The references
    /// correspond to the MPC VM.
    outputs: Vec<(Slice, DecodeFuture<BitVec>)>,
    /// Whether the DEAP VM should operate in a limited mode.
    ///
    /// The following limitations will apply:
    ///
    /// - `wants_flush`, `flush`, `wants_preprocess`, `preprocess` will **NOT**
    ///   have an effect on the ZK VM, only on the MPC VM.
    /// - `call_raw` will **not** accept calls which have AND gates.
    ///
    /// This mode facilitates the ZK VM preprocessing in an
    /// external context concurrently with the execution of the DEAP VM.
    limited: bool,
}

impl<Mpc, Zk> Deap<Mpc, Zk> {
    /// Creates a new DEAP VM.
    pub fn new(role: Role, mpc: Mpc, zk: Zk) -> Self {
        Self {
            role,
            mpc: Arc::new(Mutex::new(mpc)),
            zk: Arc::new(Mutex::new(zk)),
            memory_map: map::MemoryMap::default(),
            follower_input_ranges: RangeSet::default(),
            follower_inputs: Vec::default(),
            outputs: Vec::default(),
            limited: false,
        }
    }

    /// Returns the MPC and ZK VMs.
    pub fn into_inner(self) -> (Mpc, Zk) {
        (
            Arc::into_inner(self.mpc).unwrap().into_inner(),
            Arc::into_inner(self.zk).unwrap().into_inner(),
        )
    }

    /// Returns a mutable reference to the ZK VM.
    ///
    /// # Panics
    ///
    /// Panics if the mutex is locked by another thread.
    pub fn zk(&self) -> MutexGuard<'_, Zk> {
        self.zk.try_lock().unwrap()
    }

    /// Returns an owned mutex guard to the ZK VM.
    ///
    /// # Panics
    ///
    /// Panics if the mutex is locked by another thread.
    pub fn zk_owned(&self) -> OwnedMutexGuard<Zk> {
        self.zk.clone().try_lock_owned().unwrap()
    }

    /// Translates a value from the MPC VM address space to the ZK VM address
    /// space.
    pub fn translate<T: Repr<Binary>>(&self, value: T) -> Result<T, VmError> {
        self.memory_map.try_get(value.to_raw()).map(T::from_raw)
    }

    /// Sets the limited mode of operation.
    pub fn limited(&mut self) {
        self.limited = true;
    }

    #[cfg(test)]
    fn mpc(&self) -> MutexGuard<'_, Mpc> {
        self.mpc.try_lock().unwrap()
    }
}

impl<Mpc, Zk> Deap<Mpc, Zk>
where
    Mpc: Vm<Binary> + Send + 'static,
    Zk: Vm<Binary> + Send + 'static,
{
    /// Finalizes the DEAP VM.
    ///
    /// This reveals all private inputs of the follower.
    pub async fn finalize(&mut self, ctx: &mut Context) -> Result<(), VmError> {
        let mut mpc = self.mpc.try_lock().unwrap();
        let mut zk = self.zk.try_lock().unwrap();

        // Decode the private inputs of the follower.
        //
        // # Security
        //
        // This assumes that the decoding process is authenticated from the leader's
        // perspective. In the case of garbled circuits, the leader should be the
        // generator such that the follower proves their inputs using their committed
        // MACs.
        let input_futs = self
            .follower_inputs
            .iter()
            .map(|&input| mpc.decode_raw(input))
            .collect::<Result<Vec<_>, _>>()?;

        mpc.execute_all(ctx).await?;

        // Assign inputs to the ZK VM.
        for (mut decode, &input) in input_futs.into_iter().zip(&self.follower_inputs) {
            let input = self.memory_map.try_get(input)?;

            // Follower has already assigned the inputs.
            if let Role::Leader = self.role {
                let value = decode
                    .try_recv()
                    .map_err(VmError::memory)?
                    .expect("input should be decoded");
                zk.assign_raw(input, value)?;
            }

            // Now the follower's inputs are public.
            zk.commit_raw(input)?;
        }

        zk.execute_all(ctx).await.map_err(VmError::execute)?;

        // Follower verifies the outputs are consistent.
        if let Role::Follower = self.role {
            for (output, mut value) in mem::take(&mut self.outputs) {
                // If the output is not available in the MPC VM, we did not execute and decode
                // it. Therefore, we do not need to check for equality.
                //
                // This can occur if some function was preprocessed but ultimately not used.
                if let Some(mpc_output) = mpc.get_raw(output)? {
                    let zk_output = value
                        .try_recv()
                        .map_err(VmError::memory)?
                        .expect("output should be decoded");

                    // Asserts equality of all the output values from both VMs.
                    if zk_output != mpc_output {
                        return Err(VmError::execute(Error::from(ErrorRepr::EqualityCheck)));
                    }
                }
            }
        }

        Ok(())
    }
}

impl<Mpc, Zk> Memory<Binary> for Deap<Mpc, Zk>
where
    Mpc: Memory<Binary, Error = VmError>,
    Zk: Memory<Binary, Error = VmError>,
{
    type Error = VmError;

    fn is_alloc_raw(&self, slice: Slice) -> bool {
        self.mpc.try_lock().unwrap().is_alloc_raw(slice)
    }

    fn alloc_raw(&mut self, size: usize) -> Result<Slice, VmError> {
        let mpc_slice = self.mpc.try_lock().unwrap().alloc_raw(size)?;
        let zk_slice = self.zk.try_lock().unwrap().alloc_raw(size)?;

        self.memory_map.insert(mpc_slice, zk_slice);

        Ok(mpc_slice)
    }

    fn is_assigned_raw(&self, slice: Slice) -> bool {
        self.mpc.try_lock().unwrap().is_assigned_raw(slice)
    }

    fn assign_raw(&mut self, slice: Slice, data: BitVec) -> Result<(), VmError> {
        self.mpc
            .try_lock()
            .unwrap()
            .assign_raw(slice, data.clone())?;

        self.zk
            .try_lock()
            .unwrap()
            .assign_raw(self.memory_map.try_get(slice)?, data)
    }

    fn is_committed_raw(&self, slice: Slice) -> bool {
        self.mpc.try_lock().unwrap().is_committed_raw(slice)
    }

    fn commit_raw(&mut self, slice: Slice) -> Result<(), VmError> {
        // Follower's private inputs are not committed in the ZK VM until finalization.
        let input_minus_follower = slice.to_range().difference(&self.follower_input_ranges);
        let mut zk = self.zk.try_lock().unwrap();
        for input in input_minus_follower.iter_ranges() {
            zk.commit_raw(
                self.memory_map
                    .try_get(Slice::from_range_unchecked(input))?,
            )?;
        }

        self.mpc.try_lock().unwrap().commit_raw(slice)
    }

    fn get_raw(&self, slice: Slice) -> Result<Option<BitVec>, VmError> {
        self.mpc.try_lock().unwrap().get_raw(slice)
    }

    fn decode_raw(&mut self, slice: Slice) -> Result<DecodeFuture<BitVec>, VmError> {
        let fut = self
            .zk
            .try_lock()
            .unwrap()
            .decode_raw(self.memory_map.try_get(slice)?)?;
        self.outputs.push((slice, fut));

        self.mpc.try_lock().unwrap().decode_raw(slice)
    }
}

impl<Mpc, Zk> View<Binary> for Deap<Mpc, Zk>
where
    Mpc: View<Binary, Error = VmError>,
    Zk: View<Binary, Error = VmError>,
{
    type Error = VmError;

    fn mark_public_raw(&mut self, slice: Slice) -> Result<(), VmError> {
        self.mpc.try_lock().unwrap().mark_public_raw(slice)?;
        self.zk
            .try_lock()
            .unwrap()
            .mark_public_raw(self.memory_map.try_get(slice)?)
    }

    fn mark_private_raw(&mut self, slice: Slice) -> Result<(), VmError> {
        let mut zk = self.zk.try_lock().unwrap();
        let mut mpc = self.mpc.try_lock().unwrap();
        match self.role {
            Role::Leader => {
                mpc.mark_private_raw(slice)?;
                zk.mark_private_raw(self.memory_map.try_get(slice)?)?;
            }
            Role::Follower => {
                mpc.mark_private_raw(slice)?;
                // Follower's private inputs will become public during finalization.
                zk.mark_public_raw(self.memory_map.try_get(slice)?)?;
                self.follower_input_ranges.union_mut(&slice.to_range());
                self.follower_inputs.push(slice);
            }
        }

        Ok(())
    }

    fn mark_blind_raw(&mut self, slice: Slice) -> Result<(), VmError> {
        let mut zk = self.zk.try_lock().unwrap();
        let mut mpc = self.mpc.try_lock().unwrap();
        match self.role {
            Role::Leader => {
                mpc.mark_blind_raw(slice)?;
                // Follower's private inputs will become public during finalization.
                zk.mark_public_raw(self.memory_map.try_get(slice)?)?;
                self.follower_input_ranges.union_mut(&slice.to_range());
                self.follower_inputs.push(slice);
            }
            Role::Follower => {
                mpc.mark_blind_raw(slice)?;
                zk.mark_blind_raw(self.memory_map.try_get(slice)?)?;
            }
        }

        Ok(())
    }
}

impl<Mpc, Zk> Callable<Binary> for Deap<Mpc, Zk>
where
    Mpc: Vm<Binary>,
    Zk: Vm<Binary>,
{
    fn call_raw(&mut self, call: Call) -> Result<Slice, VmError> {
        if self.limited && call.circ().and_count() > 0 {
            return Err(VmError::call(
                "calls with AND gates not allowed in limited mode",
            ));
        }

        let (circ, inputs) = call.clone().into_parts();
        let mut builder = Call::builder(circ);

        for input in inputs {
            builder = builder.arg(self.memory_map.try_get(input)?);
        }

        let zk_call = builder.build().expect("call should be valid");

        let output = self.mpc.try_lock().unwrap().call_raw(call)?;
        let zk_output = self.zk.try_lock().unwrap().call_raw(zk_call)?;

        self.memory_map.insert(output, zk_output);

        Ok(output)
    }
}

#[async_trait]
impl<Mpc, Zk> Execute for Deap<Mpc, Zk>
where
    Mpc: Execute + Send + 'static,
    Zk: Execute + Send + 'static,
{
    fn wants_flush(&self) -> bool {
        if self.limited {
            self.mpc.try_lock().unwrap().wants_flush()
        } else {
            self.mpc.try_lock().unwrap().wants_flush() || self.zk.try_lock().unwrap().wants_flush()
        }
    }

    async fn flush(&mut self, ctx: &mut Context) -> Result<(), VmError> {
        let mut mpc = self.mpc.clone().try_lock_owned().unwrap();

        let zk = if self.limited {
            None
        } else {
            Some(self.zk.clone().try_lock_owned().unwrap())
        };

        ctx.try_join(
            async move |ctx| {
                if let Some(mut zk) = zk {
                    zk.flush(ctx).await.unwrap();
                }
                Ok(())
            },
            async move |ctx| mpc.flush(ctx).await,
        )
        .await
        .map_err(VmError::execute)??;

        Ok(())
    }

    fn wants_preprocess(&self) -> bool {
        if self.limited {
            self.mpc.try_lock().unwrap().wants_preprocess()
        } else {
            self.mpc.try_lock().unwrap().wants_preprocess()
                || self.zk.try_lock().unwrap().wants_preprocess()
        }
    }

    async fn preprocess(&mut self, ctx: &mut Context) -> Result<(), VmError> {
        let mut mpc = self.mpc.clone().try_lock_owned().unwrap();

        let zk = if self.limited {
            None
        } else {
            Some(self.zk.clone().try_lock_owned().unwrap())
        };

        ctx.try_join(
            async move |ctx| {
                if let Some(mut zk) = zk {
                    zk.preprocess(ctx).await.unwrap();
                }
                Ok(())
            },
            async move |ctx| mpc.preprocess(ctx).await,
        )
        .await
        .map_err(VmError::execute)??;

        Ok(())
    }

    fn wants_execute(&self) -> bool {
        self.mpc.try_lock().unwrap().wants_execute()
    }

    async fn execute(&mut self, ctx: &mut Context) -> Result<(), VmError> {
        // Only MPC VM is executed until finalization.
        self.mpc.try_lock().unwrap().execute(ctx).await
    }
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub(crate) struct DeapError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("equality check failed")]
    EqualityCheck,
}

#[cfg(test)]
mod tests {
    use mpz_circuits::circuits::AES128;
    use mpz_common::context::test_st_context;
    use mpz_core::Block;
    use mpz_garble::protocol::semihonest::{Evaluator, Garbler};
    use mpz_ot::ideal::{cot::ideal_cot, rcot::ideal_rcot};
    use mpz_vm_core::{
        memory::{binary::U8, correlated::Delta, Array},
        prelude::*,
    };
    use mpz_zk::{Prover, Verifier};
    use rand::{rngs::StdRng, SeedableRng};

    use super::*;

    #[tokio::test]
    async fn test_deap() {
        let mut rng = StdRng::seed_from_u64(0);
        let delta_mpc = Delta::random(&mut rng);
        let delta_zk = Delta::random(&mut rng);

        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let (rcot_send, rcot_recv) = ideal_rcot(Block::ZERO, delta_zk.into_inner());
        let (cot_send, cot_recv) = ideal_cot(delta_mpc.into_inner());

        let gb = Garbler::new(cot_send, [0u8; 16], delta_mpc);
        let ev = Evaluator::new(cot_recv);
        let prover = Prover::new(rcot_recv);
        let verifier = Verifier::new(delta_zk, rcot_send);

        let mut leader = Deap::new(Role::Leader, gb, prover);
        let mut follower = Deap::new(Role::Follower, ev, verifier);

        let (ct_leader, ct_follower) = futures::join!(
            async {
                let key: Array<U8, 16> = leader.alloc().unwrap();
                let msg: Array<U8, 16> = leader.alloc().unwrap();

                leader.mark_private(key).unwrap();
                leader.mark_blind(msg).unwrap();
                leader.assign(key, [42u8; 16]).unwrap();
                leader.commit(key).unwrap();
                leader.commit(msg).unwrap();

                let ct: Array<U8, 16> = leader
                    .call(
                        Call::builder(AES128.clone())
                            .arg(key)
                            .arg(msg)
                            .build()
                            .unwrap(),
                    )
                    .unwrap();
                let ct = leader.decode(ct).unwrap();

                leader.flush(&mut ctx_a).await.unwrap();
                leader.execute(&mut ctx_a).await.unwrap();
                leader.flush(&mut ctx_a).await.unwrap();
                leader.finalize(&mut ctx_a).await.unwrap();

                ct.await.unwrap()
            },
            async {
                let key: Array<U8, 16> = follower.alloc().unwrap();
                let msg: Array<U8, 16> = follower.alloc().unwrap();

                follower.mark_blind(key).unwrap();
                follower.mark_private(msg).unwrap();
                follower.assign(msg, [69u8; 16]).unwrap();
                follower.commit(key).unwrap();
                follower.commit(msg).unwrap();

                let ct: Array<U8, 16> = follower
                    .call(
                        Call::builder(AES128.clone())
                            .arg(key)
                            .arg(msg)
                            .build()
                            .unwrap(),
                    )
                    .unwrap();
                let ct = follower.decode(ct).unwrap();

                follower.flush(&mut ctx_b).await.unwrap();
                follower.execute(&mut ctx_b).await.unwrap();
                follower.flush(&mut ctx_b).await.unwrap();
                follower.finalize(&mut ctx_b).await.unwrap();

                ct.await.unwrap()
            }
        );

        assert_eq!(ct_leader, ct_follower);
    }

    #[tokio::test]
    async fn test_deap_desync_memory() {
        let mut rng = StdRng::seed_from_u64(0);
        let delta_mpc = Delta::random(&mut rng);
        let delta_zk = Delta::random(&mut rng);

        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let (rcot_send, rcot_recv) = ideal_rcot(Block::ZERO, delta_zk.into_inner());
        let (cot_send, cot_recv) = ideal_cot(delta_mpc.into_inner());

        let gb = Garbler::new(cot_send, [0u8; 16], delta_mpc);
        let ev = Evaluator::new(cot_recv);
        let prover = Prover::new(rcot_recv);
        let verifier = Verifier::new(delta_zk, rcot_send);

        let mut leader = Deap::new(Role::Leader, gb, prover);
        let mut follower = Deap::new(Role::Follower, ev, verifier);

        // Desynchronize the memories.
        let _ = leader.zk().alloc_raw(1).unwrap();
        let _ = follower.zk().alloc_raw(1).unwrap();

        let (ct_leader, ct_follower) = futures::join!(
            async {
                let key: Array<U8, 16> = leader.alloc().unwrap();
                let msg: Array<U8, 16> = leader.alloc().unwrap();

                leader.mark_private(key).unwrap();
                leader.mark_blind(msg).unwrap();
                leader.assign(key, [42u8; 16]).unwrap();
                leader.commit(key).unwrap();
                leader.commit(msg).unwrap();

                let ct: Array<U8, 16> = leader
                    .call(
                        Call::builder(AES128.clone())
                            .arg(key)
                            .arg(msg)
                            .build()
                            .unwrap(),
                    )
                    .unwrap();
                let ct = leader.decode(ct).unwrap();

                leader.flush(&mut ctx_a).await.unwrap();
                leader.execute(&mut ctx_a).await.unwrap();
                leader.flush(&mut ctx_a).await.unwrap();
                leader.finalize(&mut ctx_a).await.unwrap();

                ct.await.unwrap()
            },
            async {
                let key: Array<U8, 16> = follower.alloc().unwrap();
                let msg: Array<U8, 16> = follower.alloc().unwrap();

                follower.mark_blind(key).unwrap();
                follower.mark_private(msg).unwrap();
                follower.assign(msg, [69u8; 16]).unwrap();
                follower.commit(key).unwrap();
                follower.commit(msg).unwrap();

                let ct: Array<U8, 16> = follower
                    .call(
                        Call::builder(AES128.clone())
                            .arg(key)
                            .arg(msg)
                            .build()
                            .unwrap(),
                    )
                    .unwrap();
                let ct = follower.decode(ct).unwrap();

                follower.flush(&mut ctx_b).await.unwrap();
                follower.execute(&mut ctx_b).await.unwrap();
                follower.flush(&mut ctx_b).await.unwrap();
                follower.finalize(&mut ctx_b).await.unwrap();

                ct.await.unwrap()
            }
        );

        assert_eq!(ct_leader, ct_follower);
    }

    // Tests that the leader can not use different inputs in each VM without
    // detection by the follower.
    #[tokio::test]
    async fn test_malicious() {
        let mut rng = StdRng::seed_from_u64(0);
        let delta_mpc = Delta::random(&mut rng);
        let delta_zk = Delta::random(&mut rng);

        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let (rcot_send, rcot_recv) = ideal_rcot(Block::ZERO, delta_zk.into_inner());
        let (cot_send, cot_recv) = ideal_cot(delta_mpc.into_inner());

        let gb = Garbler::new(cot_send, [1u8; 16], delta_mpc);
        let ev = Evaluator::new(cot_recv);
        let prover = Prover::new(rcot_recv);
        let verifier = Verifier::new(delta_zk, rcot_send);

        let mut leader = Deap::new(Role::Leader, gb, prover);
        let mut follower = Deap::new(Role::Follower, ev, verifier);

        let (_, follower_res) = futures::join!(
            async {
                let key: Array<U8, 16> = leader.alloc().unwrap();
                let msg: Array<U8, 16> = leader.alloc().unwrap();

                leader.mark_private(key).unwrap();
                leader.mark_blind(msg).unwrap();

                // Use different inputs in each VM.
                leader.mpc().assign(key, [42u8; 16]).unwrap();
                leader
                    .zk
                    .try_lock()
                    .unwrap()
                    .assign(key, [69u8; 16])
                    .unwrap();

                leader.commit(key).unwrap();
                leader.commit(msg).unwrap();

                let ct: Array<U8, 16> = leader
                    .call(
                        Call::builder(AES128.clone())
                            .arg(key)
                            .arg(msg)
                            .build()
                            .unwrap(),
                    )
                    .unwrap();
                let ct = leader.decode(ct).unwrap();

                leader.flush(&mut ctx_a).await.unwrap();
                leader.execute(&mut ctx_a).await.unwrap();
                leader.flush(&mut ctx_a).await.unwrap();
                leader.finalize(&mut ctx_a).await.unwrap();

                ct.await.unwrap()
            },
            async {
                let key: Array<U8, 16> = follower.alloc().unwrap();
                let msg: Array<U8, 16> = follower.alloc().unwrap();

                follower.mark_blind(key).unwrap();
                follower.mark_private(msg).unwrap();
                follower.assign(msg, [69u8; 16]).unwrap();
                follower.commit(key).unwrap();
                follower.commit(msg).unwrap();

                let ct: Array<U8, 16> = follower
                    .call(
                        Call::builder(AES128.clone())
                            .arg(key)
                            .arg(msg)
                            .build()
                            .unwrap(),
                    )
                    .unwrap();
                drop(follower.decode(ct).unwrap());

                follower.flush(&mut ctx_b).await.unwrap();
                follower.execute(&mut ctx_b).await.unwrap();
                follower.flush(&mut ctx_b).await.unwrap();
                follower.finalize(&mut ctx_b).await
            }
        );

        assert!(follower_res.is_err());
    }
}
