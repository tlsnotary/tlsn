//! TLS 1.2 PRF function.

use std::collections::VecDeque;

use crate::{hmac::reduced::HmacReduced, tls12::merge_vectors, FError};
use mpz_vm_core::{
    memory::{
        binary::{Binary, U8},
        MemoryExt, Vector,
    },
    Vm,
};

#[derive(Debug)]
pub(crate) struct PrfFunction {
    // The human-readable label, e.g. "master secret".
    label: &'static [u8],
    // The start seed and the label, e.g. client_random + server_random + "master_secret".
    start_seed_label: Option<Vec<u8>>,
    state: State,
    /// A_Hash functionalities for each iteration instantiated with the PRF
    /// secret.
    a_hash: VecDeque<HmacReduced>,
    /// P_Hash functionalities for each iteration instantiated with the PRF
    /// secret.
    p_hash: VecDeque<HmacReduced>,
    output: Vector<U8>,
}

impl PrfFunction {
    const MS_LABEL: &[u8] = b"master secret";
    const KEY_LABEL: &[u8] = b"key expansion";
    const CF_LABEL: &[u8] = b"client finished";
    const SF_LABEL: &[u8] = b"server finished";

    /// Allocates master secret.
    pub(crate) fn alloc_master_secret(
        vm: &mut dyn Vm<Binary>,
        hmac: HmacReduced,
    ) -> Result<Self, FError> {
        Self::alloc(vm, Self::MS_LABEL, hmac, 48)
    }

    /// Allocates key expansion.
    pub(crate) fn alloc_key_expansion(
        vm: &mut dyn Vm<Binary>,
        hmac: HmacReduced,
    ) -> Result<Self, FError> {
        Self::alloc(vm, Self::KEY_LABEL, hmac, 40)
    }

    /// Allocates client finished.
    pub(crate) fn alloc_client_finished(
        vm: &mut dyn Vm<Binary>,
        hmac: HmacReduced,
    ) -> Result<Self, FError> {
        Self::alloc(vm, Self::CF_LABEL, hmac, 12)
    }

    /// Allocates server finished.
    pub(crate) fn alloc_server_finished(
        vm: &mut dyn Vm<Binary>,
        hmac: HmacReduced,
    ) -> Result<Self, FError> {
        Self::alloc(vm, Self::SF_LABEL, hmac, 12)
    }

    /// Allocates a new PRF with the given `hmac` instantiated with the PRF
    /// secret.
    fn alloc(
        vm: &mut dyn Vm<Binary>,
        label: &'static [u8],
        hmac: HmacReduced,
        output_len: usize,
    ) -> Result<Self, FError> {
        assert!(output_len > 0, "cannot compute 0 bytes for prf");

        let iterations = output_len.div_ceil(32);
        let mut a_hash = VecDeque::with_capacity(iterations);
        let mut p_hash = VecDeque::with_capacity(iterations);

        // Create the required amount of HMAC instances.
        let mut hmacs = vec![hmac];
        for _ in 0..iterations * 2 - 1 {
            hmacs.push(HmacReduced::from_other(vm, &hmacs[0])?);
        }

        let mut p_out: Vec<Vector<U8>> = Vec::with_capacity(iterations);
        for _ in 0..iterations {
            let a = hmacs.pop().expect("enough instances");
            let p = hmacs.pop().expect("enough instances");
            // Decode output as soon as it becomes available.
            std::mem::drop(vm.decode(a.output()).map_err(FError::vm)?);
            p_out.push(p.output().into());

            a_hash.push_back(a);
            p_hash.push_back(p);
        }

        Ok(Self {
            label,
            start_seed_label: None,
            state: State::WantsSeed,
            a_hash,
            p_hash,
            output: merge_vectors(vm, p_out, output_len)?,
        })
    }

    /// Whether this functionality needs to be flushed.
    pub(crate) fn wants_flush(&self) -> bool {
        let state_wants_flush = match self.state {
            State::WantsSeed => self.start_seed_label.is_some(),
            State::ComputeFirstCycle { .. } => true,
            State::ComputeCycle { .. } => true,
            State::ComputeLastCycle { .. } => true,
            _ => false,
        };

        state_wants_flush
            || self.a_hash.iter().any(|h| h.wants_flush())
            || self.p_hash.iter().any(|h| h.wants_flush())
    }

    /// Flushes the functionality.
    pub(crate) fn flush(&mut self, vm: &mut dyn Vm<Binary>) -> Result<(), FError> {
        // Flush every HMAC functionality.
        self.a_hash.iter_mut().try_for_each(|h| h.flush(vm))?;
        self.p_hash.iter_mut().try_for_each(|h| h.flush(vm))?;

        match &self.state {
            State::WantsSeed => {
                if let Some(seed) = &self.start_seed_label {
                    self.state = State::ComputeFirstCycle { msg: seed.to_vec() };
                    // recurse.
                    self.flush(vm)?;
                }
            }
            State::ComputeFirstCycle { msg } => {
                let mut a = self.a_hash.pop_front().expect("not empty");

                if !a.is_msg_set() {
                    a.set_msg(msg)?;
                    a.flush(vm)?;
                }

                let out = if a.is_complete() {
                    let mut a_out = vm.decode(a.output()).map_err(FError::vm)?;
                    a_out.try_recv().map_err(FError::vm)?
                } else {
                    None
                };

                match out {
                    Some(out) => {
                        self.state = State::ComputeCycle { msg: out.to_vec() };
                        // Recurse to the next cycle.
                        self.flush(vm)?;
                    }
                    None => {
                        // Prepare to process this cycle again after VM executes.
                        self.a_hash.push_front(a);
                        self.state = State::ComputeFirstCycle { msg: msg.to_vec() };
                    }
                }
            }
            State::ComputeCycle { msg } => {
                if self.p_hash.len() == 1 {
                    // Recurse to the last cycle.
                    self.state = State::ComputeLastCycle { msg: msg.to_vec() };
                    self.flush(vm)?;
                    return Ok(());
                }

                let mut a = self.a_hash.pop_front().expect("not empty");
                let mut p = self.p_hash.pop_front().expect("not empty");

                if !a.is_msg_set() {
                    a.set_msg(msg)?;
                    a.flush(vm)?;
                }

                if !p.is_msg_set() {
                    let mut p_msg = msg.clone();
                    p_msg.extend_from_slice(
                        self.start_seed_label
                            .as_ref()
                            .expect("Start seed should have been set"),
                    );
                    p.set_msg(&p_msg)?;
                    p.flush(vm)?;
                }

                if !p.is_complete() {
                    // Prepare to process this cycle again after VM executes.
                    self.a_hash.push_front(a);
                    self.p_hash.push_front(p);
                    self.state = State::ComputeCycle { msg: msg.to_vec() };
                    return Ok(());
                }

                let out = if a.is_complete() {
                    let mut a_out = vm.decode(a.output()).map_err(FError::vm)?;
                    a_out.try_recv().map_err(FError::vm)?
                } else {
                    None
                };

                match out {
                    Some(out) => {
                        // Recurse to the next cycle.
                        self.state = State::ComputeCycle { msg: out.to_vec() };
                        self.flush(vm)?;
                    }
                    None => {
                        // Prepare to process this cycle again after VM executes.
                        self.a_hash.push_front(a);
                        self.p_hash.push_front(p);
                        self.state = State::ComputeCycle { msg: msg.to_vec() };
                    }
                }
            }
            State::ComputeLastCycle { msg } => {
                let mut p = self.p_hash.pop_front().expect("not empty");

                if !p.is_msg_set() {
                    let mut p_msg = msg.clone();
                    p_msg.extend_from_slice(
                        self.start_seed_label
                            .as_ref()
                            .expect("Start seed should have been set"),
                    );
                    p.set_msg(&p_msg)?;
                    p.flush(vm)?;
                }

                if !p.is_complete() {
                    // Prepare to process this cycle again after VM executes.
                    self.p_hash.push_front(p);
                    self.state = State::ComputeLastCycle { msg: msg.to_vec() };
                } else {
                    self.state = State::Complete;
                }
            }
            _ => (),
        }

        Ok(())
    }

    /// Sets the seed.
    pub(crate) fn set_start_seed(&mut self, seed: Vec<u8>) {
        let mut start_seed_label = self.label.to_vec();
        start_seed_label.extend_from_slice(&seed);

        self.start_seed_label = Some(start_seed_label);
    }

    /// Returns the PRF output.
    pub(crate) fn output(&self) -> Vector<U8> {
        self.output
    }

    /// Whether this functionality is complete.
    pub(crate) fn is_complete(&self) -> bool {
        matches!(self.state, State::Complete)
    }
}

#[derive(Debug, PartialEq)]
enum State {
    WantsSeed,
    /// To minimize the amount of VM execute calls, the PRF iterations are
    /// divided into cycles.
    /// Starting with iteration count i == 1, each cycle computes a tuple
    /// (A_Hash(i), P_Hash(i-1)). Thus, during the first cycle, only A_Hash(1)
    /// is computed and during the last cycle only P_Hash(i) is computed.
    ComputeFirstCycle {
        msg: Vec<u8>,
    },
    ComputeCycle {
        msg: Vec<u8>,
    },
    ComputeLastCycle {
        msg: Vec<u8>,
    },
    Complete,
}
