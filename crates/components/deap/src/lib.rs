//! Dual-execution with Asymmetric Privacy (DEAP) protocol.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

use std::{mem, ops::DerefMut, sync::Arc};

use async_trait::async_trait;
use mpz_common::{scoped_futures::ScopedFutureExt as _, Context};
use mpz_core::bitvec::BitVec;
use mpz_vm_core::{
    memory::{binary::Binary, DecodeFuture, Memory, Slice, View},
    Call, Callable, Execute, Vm, VmError,
};
use tokio::sync::Mutex;

type Error = DeapError;

/// The role of the DEAP VM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum Role {
    Leader,
    Follower,
}

/// DEAP Vm.
#[derive(Debug)]
pub struct Deap<Mpc, Zk> {
    role: Role,
    mpc: Arc<Mutex<Mpc>>,
    zk: Arc<Mutex<Zk>>,
    /// Private inputs of the follower.
    follower_inputs: Vec<Slice>,
    outputs: Vec<(Slice, DecodeFuture<BitVec>)>,
}

impl<Mpc, Zk> Deap<Mpc, Zk> {
    /// Create a new DEAP Vm.
    pub fn new(role: Role, mpc: Mpc, zk: Zk) -> Self {
        Self {
            role,
            mpc: Arc::new(Mutex::new(mpc)),
            zk: Arc::new(Mutex::new(zk)),
            follower_inputs: Vec::default(),
            outputs: Vec::default(),
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
    pub fn zk(&self) -> impl DerefMut<Target = Zk> + '_ {
        self.zk.try_lock().unwrap()
    }

    /// Returns a mutable reference to the MPC VM.
    pub fn mpc(&self) -> impl DerefMut<Target = Mpc> + '_ {
        self.mpc.try_lock().unwrap()
    }
}

impl<Mpc, Zk> Deap<Mpc, Zk>
where
    Mpc: Vm<Binary>,
    Zk: Vm<Binary>,
{
    /// Finalize the DEAP Vm.
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
            .map(|input| mpc.decode_raw(*input))
            .collect::<Result<Vec<_>, _>>()?;
        mpc.flush(ctx).await?;

        // Assign inputs to the ZK VM.
        for (mut decode, input) in input_futs
            .into_iter()
            .zip(mem::take(&mut self.follower_inputs))
        {
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

        zk.flush(ctx).await?;
        zk.execute(ctx).await?;
        zk.flush(ctx).await?;

        // Follower verifies the outputs are consistent.
        if let Role::Follower = self.role {
            for (output, mut value) in mem::take(&mut self.outputs) {
                let zk_output = value
                    .try_recv()
                    .map_err(VmError::memory)?
                    .expect("output should be decoded");
                let mpc_output = mpc.get_raw(output)?.expect("output should be decoded");

                // Asserts equality of all the output values from both VMs.
                if zk_output != mpc_output {
                    return Err(VmError::execute(Error::from(ErrorRepr::EqualityCheck)));
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

    fn alloc_raw(&mut self, size: usize) -> Result<Slice, VmError> {
        self.zk().alloc_raw(size)?;
        self.mpc().alloc_raw(size)
    }

    fn assign_raw(&mut self, slice: Slice, data: BitVec) -> Result<(), VmError> {
        self.zk().assign_raw(slice, data.clone())?;
        self.mpc().assign_raw(slice, data)
    }

    fn commit_raw(&mut self, slice: Slice) -> Result<(), VmError> {
        // Follower's private inputs are not committed in the ZK VM until finalization.
        if !self.follower_inputs.contains(&slice) {
            self.zk().commit_raw(slice)?;
        }

        self.mpc().commit_raw(slice)
    }

    fn get_raw(&self, slice: Slice) -> Result<Option<BitVec>, VmError> {
        self.mpc().get_raw(slice)
    }

    fn decode_raw(&mut self, slice: Slice) -> Result<DecodeFuture<BitVec>, VmError> {
        let fut = self.zk().decode_raw(slice)?;
        self.outputs.push((slice, fut));

        self.mpc().decode_raw(slice)
    }
}

impl<Mpc, Zk> View<Binary> for Deap<Mpc, Zk>
where
    Mpc: View<Binary, Error = VmError>,
    Zk: View<Binary, Error = VmError>,
{
    type Error = VmError;

    fn mark_public_raw(&mut self, slice: Slice) -> Result<(), VmError> {
        self.zk().mark_public_raw(slice)?;
        self.mpc().mark_public_raw(slice)
    }

    fn mark_private_raw(&mut self, slice: Slice) -> Result<(), VmError> {
        let mut zk = self.zk.try_lock().unwrap();
        let mut mpc = self.mpc.try_lock().unwrap();
        match self.role {
            Role::Leader => {
                zk.mark_private_raw(slice)?;
                mpc.mark_private_raw(slice)?;
            }
            Role::Follower => {
                // Follower's private inputs will become public during finalization.
                zk.mark_public_raw(slice)?;
                mpc.mark_private_raw(slice)?;
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
                // Follower's private inputs will become public during finalization.
                zk.mark_public_raw(slice)?;
                mpc.mark_blind_raw(slice)?;
                self.follower_inputs.push(slice);
            }
            Role::Follower => {
                zk.mark_blind_raw(slice)?;
                mpc.mark_blind_raw(slice)?;
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
        self.zk().call_raw(call.clone())?;
        self.mpc().call_raw(call)
    }
}

#[async_trait]
impl<Mpc, Zk> Execute for Deap<Mpc, Zk>
where
    Mpc: Execute + Send + 'static,
    Zk: Execute + Send + 'static,
{
    async fn flush(&mut self, ctx: &mut Context) -> Result<(), VmError> {
        let mut zk = self.zk.clone().try_lock_owned().unwrap();
        let mut mpc = self.mpc.clone().try_lock_owned().unwrap();
        ctx.try_join(
            |ctx| async move { zk.flush(ctx).await }.scope_boxed(),
            |ctx| async move { mpc.flush(ctx).await }.scope_boxed(),
        )
        .await
        .map_err(VmError::execute)??;

        Ok(())
    }

    async fn preprocess(&mut self, ctx: &mut Context) -> Result<(), VmError> {
        let mut zk = self.zk.clone().try_lock_owned().unwrap();
        let mut mpc = self.mpc.clone().try_lock_owned().unwrap();
        ctx.try_join(
            |ctx| async move { zk.preprocess(ctx).await }.scope_boxed(),
            |ctx| async move { mpc.preprocess(ctx).await }.scope_boxed(),
        )
        .await
        .map_err(VmError::execute)??;

        Ok(())
    }

    async fn execute(&mut self, ctx: &mut Context) -> Result<(), VmError> {
        // Only MPC VM is executed until finalization.
        self.mpc().execute(ctx).await
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
    use mpz_garble::protocol::semihonest::{Evaluator, Generator};
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
        let delta = Delta::random(&mut rng);

        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let (rcot_send, rcot_recv) = ideal_rcot(Block::ZERO, delta.into_inner());
        let (cot_send, cot_recv) = ideal_cot(delta.into_inner());

        let gb = Generator::new(cot_send, [0u8; 16], delta);
        let ev = Evaluator::new(cot_recv);
        let prover = Prover::new(rcot_recv);
        let verifier = Verifier::new(delta, rcot_send);

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
                    .call(Call::new(AES128.clone()).arg(key).arg(msg).build().unwrap())
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
                    .call(Call::new(AES128.clone()).arg(key).arg(msg).build().unwrap())
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
        let delta = Delta::random(&mut rng);

        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let (rcot_send, rcot_recv) = ideal_rcot(Block::ZERO, delta.into_inner());
        let (cot_send, cot_recv) = ideal_cot(delta.into_inner());

        let gb = Generator::new(cot_send, [0u8; 16], delta);
        let ev = Evaluator::new(cot_recv);
        let prover = Prover::new(rcot_recv);
        let verifier = Verifier::new(delta, rcot_send);

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
                leader.zk().assign(key, [69u8; 16]).unwrap();

                leader.commit(key).unwrap();
                leader.commit(msg).unwrap();

                let ct: Array<U8, 16> = leader
                    .call(Call::new(AES128.clone()).arg(key).arg(msg).build().unwrap())
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
                    .call(Call::new(AES128.clone()).arg(key).arg(msg).build().unwrap())
                    .unwrap();
                let _ = follower.decode(ct).unwrap();

                follower.flush(&mut ctx_b).await.unwrap();
                follower.execute(&mut ctx_b).await.unwrap();
                follower.flush(&mut ctx_b).await.unwrap();
                follower.finalize(&mut ctx_b).await
            }
        );

        assert!(follower_res.is_err());
    }
}
