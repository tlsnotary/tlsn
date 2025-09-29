use mpz_hash::sha256::Sha256;
use mpz_vm_core::{
    memory::{
        binary::{Binary, U32, U8},
        Array, MemoryExt, Vector, ViewExt,
    },
    Vm,
};

use crate::{
    hmac::{compute_partial, hmac_sha256, IPAD, OPAD},
    FError,
};

/// Functionality for HMAC computation with a private key and a public message.
///
/// Used in conjunction with [crate::Mode::Normal].
#[derive(Debug, Clone)]
pub(crate) struct HmacNormal {
    inner_partial: Sha256,
    outer_partial: Sha256,
    output: Option<Array<U8, 32>>,
    state: State,
}

impl HmacNormal {
    /// Allocates a new HMAC with the given `key`.
    pub(crate) fn alloc(vm: &mut dyn Vm<Binary>, key: Vector<U8>) -> Result<Self, FError> {
        Ok(Self {
            inner_partial: compute_partial(vm, key, IPAD)?,
            outer_partial: compute_partial(vm, key, OPAD)?,
            output: None,
            state: State::WantsMsg,
        })
    }

    /// Allocates a new HMAC with the given `inner_partial` and
    /// `outer_partial`.
    pub(crate) fn alloc_with_state(
        vm: &mut dyn Vm<Binary>,
        inner_partial: [u32; 8],
        outer_partial: [u32; 8],
    ) -> Result<Self, FError> {
        let inner_p: Array<U32, 8> = vm.alloc().map_err(FError::vm)?;
        vm.mark_public(inner_p).map_err(FError::vm)?;
        vm.assign(inner_p, inner_partial).map_err(FError::vm)?;
        vm.commit(inner_p).map_err(FError::vm)?;
        let inner = Sha256::new_from_state(inner_p, 1);

        let outer_p: Array<U32, 8> = vm.alloc().map_err(FError::vm)?;
        vm.mark_public(outer_p).map_err(FError::vm)?;
        vm.assign(outer_p, outer_partial).map_err(FError::vm)?;
        vm.commit(outer_p).map_err(FError::vm)?;
        let outer = Sha256::new_from_state(outer_p, 1);

        Ok(Self {
            inner_partial: inner,
            outer_partial: outer,
            output: None,
            state: State::WantsMsg,
        })
    }

    /// Whether this functionality needs to be flushed.
    pub(crate) fn wants_flush(&self) -> bool {
        matches!(self.state, State::MsgSet)
    }

    /// Flushes the functionality.
    pub(crate) fn flush(&mut self) -> Result<(), FError> {
        if let State::MsgSet = self.state {
            self.state = State::Complete;
        }

        Ok(())
    }

    /// Sets an HMAC message `msg`.
    ///
    /// The message is a slice of vectors which will be concatenated.
    pub(crate) fn set_msg(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        msg: &[Vector<U8>],
    ) -> Result<(), FError> {
        match self.state {
            State::WantsMsg => (),
            _ => return Err(FError::state("must be in WantsMsg state to set message")),
        }

        msg.iter().for_each(|m| self.inner_partial.update(m));
        self.inner_partial.compress(vm).map_err(FError::vm)?;
        let inner_local = self.inner_partial.finalize(vm).map_err(FError::vm)?;
        let out = hmac_sha256(vm, self.outer_partial.clone(), inner_local)?;

        self.output = Some(out);
        self.state = State::MsgSet;

        Ok(())
    }

    /// Returns HMAC output.
    pub(crate) fn output(&self) -> Result<Array<U8, 32>, FError> {
        match self.state {
            State::MsgSet | State::Complete => Ok(self
                .output
                .expect("output is available when message is set")),
            _ => Err(FError::state(
                "must be in MsgSet or Complete state to return output",
            )),
        }
    }

    /// Creates a new allocated instance of HMAC from another instance.
    pub(crate) fn from_other(other: &Self) -> Result<Self, FError> {
        match other.state {
            State::WantsMsg => Ok(Self {
                inner_partial: other.inner_partial.clone(),
                outer_partial: other.outer_partial.clone(),
                output: None,
                state: State::WantsMsg,
            }),

            _ => Err(FError::state("other must be in WantsMsg state")),
        }
    }

    /// Whether this functionality is complete.
    pub(crate) fn is_complete(&self) -> bool {
        matches!(self.state, State::Complete)
    }
}

/// State of [HmacNormal].
#[derive(Debug, Clone)]
pub(crate) enum State {
    WantsMsg,
    /// The state after the message has been set.
    MsgSet,
    Complete,
}
