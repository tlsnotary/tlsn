//! TLS 1.2 PRF function.

use crate::{hmac::normal::HmacNormal, tls12::merge_vectors, FError};
use mpz_vm_core::{
    memory::{
        binary::{Binary, U8},
        MemoryExt, Vector, ViewExt,
    },
    Vm,
};

#[derive(Debug)]
pub(crate) struct PrfFunction {
    // The human-readable label, e.g. "master secret".
    label: &'static [u8],
    state: State,
    /// The start seed and the label, e.g. client_random + server_random +
    /// "master_secret".
    start_seed_label: Option<Vec<u8>>,
    seed_label_ref: Vector<U8>,
    /// A_Hash functionalities for each iteration instantiated with the PRF
    /// secret.
    a_hash: Vec<HmacNormal>,
    /// P_Hash functionalities for each iteration instantiated with the PRF
    /// secret.
    p_hash: Vec<HmacNormal>,
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
        hmac: HmacNormal,
    ) -> Result<Self, FError> {
        Self::alloc(vm, Self::MS_LABEL, hmac, 48, 64)
    }

    /// Allocates key expansion.
    pub(crate) fn alloc_key_expansion(
        vm: &mut dyn Vm<Binary>,
        hmac: HmacNormal,
    ) -> Result<Self, FError> {
        Self::alloc(vm, Self::KEY_LABEL, hmac, 40, 64)
    }

    /// Allocates client finished.
    pub(crate) fn alloc_client_finished(
        vm: &mut dyn Vm<Binary>,
        hmac: HmacNormal,
    ) -> Result<Self, FError> {
        Self::alloc(vm, Self::CF_LABEL, hmac, 12, 32)
    }

    /// Allocates server finished.
    pub(crate) fn alloc_server_finished(
        vm: &mut dyn Vm<Binary>,
        hmac: HmacNormal,
    ) -> Result<Self, FError> {
        Self::alloc(vm, Self::SF_LABEL, hmac, 12, 32)
    }

    /// Allocates a new PRF with the given `hmac` instantiated with the PRF
    /// secret.
    fn alloc(
        vm: &mut dyn Vm<Binary>,
        label: &'static [u8],
        hmac: HmacNormal,
        output_len: usize,
        seed_len: usize,
    ) -> Result<Self, FError> {
        assert!(output_len > 0, "cannot compute 0 bytes for prf");

        let iterations = output_len.div_ceil(32);

        let msg_len_a = label.len() + seed_len;
        let seed_label_ref: Vector<U8> = vm.alloc_vec(msg_len_a).map_err(FError::vm)?;
        vm.mark_public(seed_label_ref).map_err(FError::vm)?;

        let mut msg_a = seed_label_ref;

        let mut p_out: Vec<Vector<U8>> = Vec::with_capacity(iterations);
        let mut a_hash = Vec::with_capacity(iterations);
        let mut p_hash = Vec::with_capacity(iterations);

        for _ in 0..iterations {
            let mut a = HmacNormal::from_other(&hmac)?;
            a.set_msg(vm, &[msg_a])?;
            let a_out: Vector<U8> = a.output()?.into();
            msg_a = a_out;
            a_hash.push(a);

            let mut p = HmacNormal::from_other(&hmac)?;
            p.set_msg(vm, &[a_out, seed_label_ref])?;
            p_out.push(p.output()?.into());
            p_hash.push(p);
        }

        Ok(Self {
            label,
            state: State::WantsSeed,
            start_seed_label: None,
            seed_label_ref,
            a_hash,
            p_hash,
            output: merge_vectors(vm, p_out, output_len)?,
        })
    }

    /// Whether this functionality needs to be flushed.
    pub(crate) fn wants_flush(&self) -> bool {
        let state_wants_flush = match self.state {
            State::WantsSeed => self.start_seed_label.is_some(),
            _ => false,
        };
        state_wants_flush
            || self.a_hash.iter().any(|h| h.wants_flush())
            || self.p_hash.iter().any(|h| h.wants_flush())
    }

    /// Flushes the functionality.
    pub(crate) fn flush(&mut self, vm: &mut dyn Vm<Binary>) -> Result<(), FError> {
        // Flush every HMAC functionality.
        self.a_hash.iter_mut().try_for_each(|h| h.flush())?;
        self.p_hash.iter_mut().try_for_each(|h| h.flush())?;

        match self.state {
            State::WantsSeed => {
                if let Some(seed) = &self.start_seed_label {
                    vm.assign(self.seed_label_ref, seed.clone())
                        .map_err(FError::vm)?;
                    vm.commit(self.seed_label_ref).map_err(FError::vm)?;

                    self.state = State::SeedSet;
                    // Recurse.
                    self.flush(vm)?;
                }
            }
            State::SeedSet => {
                // We are complete when all HMACs are complete.
                if self.a_hash.iter().all(|h| h.is_complete())
                    && self.p_hash.iter().all(|h| h.is_complete())
                {
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

#[derive(Debug, Clone, Copy)]
enum State {
    WantsSeed,
    SeedSet,
    Complete,
}
