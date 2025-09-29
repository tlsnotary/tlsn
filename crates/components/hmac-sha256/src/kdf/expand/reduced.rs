use mpz_vm_core::{
    memory::{
        binary::{Binary, U8},
        Vector,
    },
    Vm,
};

use crate::{hmac::reduced::HmacReduced, kdf::expand::label::HkdfLabelClear, FError};

/// Functionality for computing `HKDF-Expand-Label` with a private secret
/// and public label and context.
#[derive(Debug)]
pub(crate) struct HkdfExpand {
    label: HkdfLabelClear,
    hmac: HmacReduced,
    ctx: Option<Vec<u8>>,
    output: Vector<U8>,
    state: State,
}

impl HkdfExpand {
    /// Allocates a new HKDF-Expand-Label with the `hmac`
    /// instantiated with the secret.
    pub(crate) fn alloc(
        hmac: HmacReduced,
        // Human-readable label.
        label: &'static [u8],
        // Output length.
        out_len: usize,
    ) -> Result<Self, FError> {
        assert!(
            out_len <= 32,
            "output length larger than 32 is not supported"
        );

        let hkdf_label = HkdfLabelClear::new(label, out_len);

        let mut output: Vector<U8> = hmac.output().into();
        output.truncate(out_len);

        Ok(Self {
            label: hkdf_label,
            hmac,
            ctx: None,
            output,
            state: State::WantsContext,
        })
    }

    /// Whether this functionality needs to be flushed.
    pub(crate) fn wants_flush(&self) -> bool {
        let state_wants_flush = match self.state {
            State::WantsContext => self.is_ctx_set(),
            _ => false,
        };

        state_wants_flush || self.hmac.wants_flush()
    }

    /// Flushes the functionality.
    pub(crate) fn flush(&mut self, vm: &mut dyn Vm<Binary>) -> Result<(), FError> {
        self.hmac.flush(vm)?;

        match self.state {
            State::WantsContext => {
                if let Some(ctx) = &self.ctx {
                    // HKDF-Expand requires 0x01 to be concatenated.
                    // see line: T(1) = HMAC-Hash(PRK, T(0) | info | 0x01) in
                    // https://datatracker.ietf.org/doc/html/rfc5869
                    self.label.set_ctx(ctx)?;
                    let mut label = self.label.output()?;
                    label.push(0x01);

                    self.hmac.set_msg(&label)?;
                    self.hmac.flush(vm)?;

                    self.state = State::ContextSet;
                    // Recurse.
                    self.flush(vm)?;
                }
            }
            State::ContextSet => {
                if self.hmac.is_complete() {
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

    /// Whether the context has been set.
    pub(crate) fn is_ctx_set(&self) -> bool {
        self.ctx.is_some()
    }

    /// Whether this functionality is complete.
    pub(crate) fn is_complete(&self) -> bool {
        matches!(self.state, State::Complete)
    }
}

#[derive(Debug)]
enum State {
    WantsContext,
    ContextSet,
    Complete,
}
