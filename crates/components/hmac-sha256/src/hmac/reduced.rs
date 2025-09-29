use crate::hmac::{assign_inner_local, compute_partial, hmac_sha256, IPAD, OPAD};
use mpz_hash::sha256::Sha256;
use mpz_vm_core::{
    memory::{
        binary::{Binary, U32, U8},
        Array, MemoryExt, Vector, ViewExt,
    },
    Vm,
};

use crate::FError;

/// Functionality for HMAC computation with a private key and a public message.
///
/// Used in conjunction with [crate::Mode::Reduced].
#[derive(Debug)]
pub(crate) struct HmacReduced {
    outer_partial: Sha256,
    inner_local: Array<U8, 32>,
    inner_partial: Array<U32, 8>,
    msg: Option<Vec<u8>>,
    output: Array<U8, 32>,
    state: State,
}

impl HmacReduced {
    /// Allocates a new HMAC with the given `key`.
    pub(crate) fn alloc(vm: &mut dyn Vm<Binary>, key: Vector<U8>) -> Result<Self, FError> {
        let inner_partial = compute_partial(vm, key, IPAD)?;
        let outer_partial = compute_partial(vm, key, OPAD)?;

        let (inner_partial, _) = inner_partial
            .state()
            .expect("state should be set for inner_partial");
        // Decode as soon as the value is computed.
        std::mem::drop(vm.decode(inner_partial).map_err(FError::vm)?);

        let inner_local: Array<U8, 32> = vm.alloc().map_err(FError::vm)?;
        vm.mark_public(inner_local).map_err(FError::vm)?;
        let out = hmac_sha256(vm, outer_partial.clone(), inner_local)?;

        Ok(Self {
            outer_partial,
            inner_local,
            inner_partial,
            msg: None,
            output: out,
            state: State::WantsInnerPartial,
        })
    }

    /// Whether this functionality needs to be flushed.
    pub(crate) fn wants_flush(&self) -> bool {
        match self.state {
            State::WantsInnerPartial => true,
            State::WantsMsg { .. } => self.msg.is_some(),
            _ => false,
        }
    }

    /// Flushes the functionality.
    pub(crate) fn flush(&mut self, vm: &mut dyn Vm<Binary>) -> Result<(), FError> {
        let state = self.state.take();

        match state {
            State::WantsInnerPartial => {
                let mut inner_partial = vm.decode(self.inner_partial).map_err(FError::vm)?;
                let Some(inner_partial) = inner_partial.try_recv().map_err(FError::vm)? else {
                    self.state = State::WantsInnerPartial;
                    return Ok(());
                };

                self.state = State::WantsMsg { inner_partial };
                // Recurse.
                self.flush(vm)?;
            }
            State::WantsMsg { inner_partial } => {
                // output is Some after msg was set
                if self.msg.is_some() {
                    assign_inner_local(
                        vm,
                        self.inner_local,
                        inner_partial,
                        &self.msg.clone().unwrap(),
                    )?;

                    self.state = State::Complete;
                } else {
                    self.state = State::WantsMsg { inner_partial };
                }
            }
            _ => self.state = state,
        }

        Ok(())
    }

    /// Sets the HMAC message.
    pub(crate) fn set_msg(&mut self, msg: &[u8]) -> Result<(), FError> {
        match self.msg {
            None => self.msg = Some(msg.to_vec()),
            Some(_) => return Err(FError::state("message has already been set")),
        }

        Ok(())
    }

    /// Whether the HMAC message has been set.
    pub(crate) fn is_msg_set(&mut self) -> bool {
        self.msg.is_some()
    }

    /// Returns the HMAC output.
    pub(crate) fn output(&self) -> Array<U8, 32> {
        self.output
    }

    /// Creates a new allocated instance of HMAC from another instance.
    pub(crate) fn from_other(vm: &mut dyn Vm<Binary>, other: &Self) -> Result<Self, FError> {
        match other.state {
            State::WantsInnerPartial => {
                let inner_local: Array<U8, 32> = vm.alloc().map_err(FError::vm)?;
                vm.mark_public(inner_local).map_err(FError::vm)?;

                let out = hmac_sha256(vm, other.outer_partial.clone(), inner_local)?;

                Ok(Self {
                    outer_partial: other.outer_partial.clone(),
                    inner_local,
                    inner_partial: other.inner_partial,
                    msg: None,
                    output: out,
                    state: State::WantsInnerPartial,
                })
            }
            _ => Err(FError::state("other must be in WantsInnerPartial state")),
        }
    }

    /// Whether this functionality is complete.
    pub(crate) fn is_complete(&self) -> bool {
        matches!(self.state, State::Complete)
    }
}

/// State of [HmacReduced].
#[derive(Debug, Clone)]
pub(crate) enum State {
    /// Wants the decoded inner_partial plaintext.
    WantsInnerPartial,
    /// Wants the message to be set.
    WantsMsg {
        inner_partial: [u32; 8],
    },
    Complete,
    Error,
}

impl State {
    pub(crate) fn take(&mut self) -> State {
        std::mem::replace(self, State::Error)
    }
}
