use mpz_vm_core::{
    memory::{
        binary::{Binary, U8},
        Array, MemoryExt, Vector, ViewExt,
    },
    Vm,
};

use crate::{hmac::normal::HmacNormal, FError};

/// Functionality for HKDF-Extract computation with private salt and public
/// IKM.
#[derive(Debug)]
pub(crate) struct HkdfExtract {
    hmac: HmacNormal,
    output: Vector<U8>,
    state: State,
}

impl HkdfExtract {
    /// Allocates a new HKDF-Extract with the given `ikm` and `hmac`
    /// instantiated with the salt.
    pub(crate) fn alloc(
        vm: &mut dyn Vm<Binary>,
        ikm: [u8; 32],
        mut hmac: HmacNormal,
    ) -> Result<Self, FError> {
        let msg: Array<U8, 32> = vm.alloc().map_err(FError::vm)?;
        vm.mark_public(msg).map_err(FError::vm)?;
        vm.assign(msg, ikm).map_err(FError::vm)?;
        vm.commit(msg).map_err(FError::vm)?;

        hmac.set_msg(vm, &[msg.into()])?;

        Ok(Self {
            output: hmac.output()?.into(),
            hmac,
            state: State::Setup {},
        })
    }

    /// Whether this functionality needs to be flushed.
    pub(crate) fn wants_flush(&self) -> bool {
        matches!(self.state, State::Setup) || self.hmac.wants_flush()
    }

    /// Flushes the functionality.
    pub(crate) fn flush(&mut self) -> Result<(), FError> {
        self.hmac.flush()?;

        if let State::Setup = &mut self.state {
            if self.hmac.is_complete() {
                self.state = State::Complete;
            }
        }

        Ok(())
    }

    /// Returns HKDF-Extract output.
    pub(crate) fn output(&self) -> Vector<U8> {
        self.output
    }

    /// Whether this functionality is complete.
    pub(crate) fn is_complete(&self) -> bool {
        matches!(self.state, State::Complete)
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub(crate) enum State {
    Setup,
    Complete,
}
