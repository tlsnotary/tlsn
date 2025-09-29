use crate::{
    hmac::normal::HmacNormal, kdf::expand::label::HkdfLabel, tls12::merge_vectors, FError,
};

use mpz_vm_core::{
    memory::{
        binary::{Binary, U8},
        MemoryExt, Vector, ViewExt,
    },
    Vm,
};

#[derive(Debug)]
enum State {
    /// Wants the context to be set.
    WantsContext,
    /// Context has been set.
    ContextSet,
    Complete,
}

/// Functionality for computing `HKDF-Expand-Label` with a private secret
/// and public label and context.
#[derive(Debug)]
pub(crate) struct HkdfExpand {
    label: HkdfLabel,
    state: State,
    ctx: Option<Vec<u8>>,
    output: Vector<U8>,
}

impl HkdfExpand {
    /// Allocates a new HKDF-Expand-Label with the `hmac`
    /// instantiated with the secret.
    pub(crate) fn alloc(
        vm: &mut dyn Vm<Binary>,
        mut hmac: HmacNormal,
        // Human-readable label.
        label: &'static [u8],
        // Context length.
        ctx_len: usize,
        // Output length.
        out_len: usize,
    ) -> Result<Self, FError> {
        assert!(
            out_len <= 32,
            "output length larger than 32 is not supported"
        );

        let hkdf_label = HkdfLabel::alloc(vm, label, ctx_len, out_len)?;
        let info = hkdf_label.output();

        // HKDF-Expand requires 0x01 to be concatenated.
        // see line: T(1) = HMAC-Hash(PRK, T(0) | info | 0x01) in
        // https://datatracker.ietf.org/doc/html/rfc5869
        let constant = vm.alloc_vec::<U8>(1).map_err(FError::vm)?;
        vm.mark_public(constant).map_err(FError::vm)?;
        vm.assign(constant, vec![0x01]).map_err(FError::vm)?;
        vm.commit(constant).map_err(FError::vm)?;

        let msg = merge_vectors(vm, vec![info, constant], info.len() + constant.len())?;

        hmac.set_msg(vm, &[msg])?;

        let mut output: Vector<U8> = hmac.output()?.into();
        output.truncate(out_len);

        Ok(Self {
            output,
            label: hkdf_label,
            ctx: None,
            state: State::WantsContext,
        })
    }

    /// Whether this functionality needs to be flushed.
    pub(crate) fn wants_flush(&self) -> bool {
        let state_wants_flush = match self.state {
            State::WantsContext => self.is_ctx_set(),
            _ => false,
        };
        state_wants_flush || self.label.wants_flush()
    }

    /// Flushes the functionality.
    pub(crate) fn flush(&mut self, vm: &mut dyn Vm<Binary>) -> Result<(), FError> {
        self.label.flush(vm)?;

        match &mut self.state {
            State::WantsContext => {
                if let Some(ctx) = &self.ctx {
                    self.label.set_ctx(ctx)?;
                    self.label.flush(vm)?;
                    self.state = State::ContextSet;
                    // Recurse.
                    self.flush(vm)?;
                }
            }
            State::ContextSet => {
                if self.label.is_complete() {
                    self.state = State::Complete;
                }
            }
            _ => (),
        }

        Ok(())
    }

    /// Sets the HKDF-Expand-Label context.
    pub(crate) fn set_ctx(&mut self, ctx: &[u8]) -> Result<(), FError> {
        if self.is_ctx_set() {
            return Err(FError::state("context has already been set"));
        }

        self.ctx = Some(ctx.to_vec());
        Ok(())
    }

    /// Returns the HKDF-Expand-Label output.
    pub(crate) fn output(&self) -> Vector<U8> {
        self.output
    }

    /// Whether this functionality is complete.
    pub(crate) fn is_complete(&self) -> bool {
        matches!(self.state, State::Complete)
    }

    /// Whether the context has been set.
    pub(crate) fn is_ctx_set(&self) -> bool {
        self.ctx.is_some()
    }
}
