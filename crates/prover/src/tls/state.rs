//! TLS prover states.
use tls_tee::TeeTlsLeader;
use tlsn_common::{
    mux::{MuxControl, MuxFuture},
    Io,
};

/// Entry state
pub struct Initialized;

opaque_debug::implement!(Initialized);

/// State after TEE setup has completed.
pub struct Setup {
    pub(crate) io: Io,
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,

    pub(crate) tee_tls: TeeTlsLeader,
}

opaque_debug::implement!(Setup);

/// State after the TLS connection has been closed.
pub struct Closed {
    pub(crate) io: Io,
    pub(crate) application_data: String,
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,
}

opaque_debug::implement!(Closed);

/// Notarizing state.
pub struct Notarize {
    pub(crate) io: Io,
    pub(crate) application_data: String,
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,
}

opaque_debug::implement!(Notarize);

impl From<Closed> for Notarize {
    fn from(state: Closed) -> Self {
        Self {
            application_data: state.application_data,
            io: state.io,
            mux_ctrl: state.mux_ctrl,
            mux_fut: state.mux_fut,
        }
    }
}

/// Proving state.
pub struct Prove {
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,
}

impl From<Closed> for Prove {
    fn from(state: Closed) -> Self {
        Self {
            mux_ctrl: state.mux_ctrl,
            mux_fut: state.mux_fut,
        }
    }
}

#[allow(missing_docs)]
pub trait ProverState: sealed::Sealed {}

impl ProverState for Initialized {}
impl ProverState for Setup {}
impl ProverState for Closed {}
impl ProverState for Notarize {}
impl ProverState for Prove {}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Initialized {}
    impl Sealed for super::Setup {}
    impl Sealed for super::Closed {}
    impl Sealed for super::Notarize {}
    impl Sealed for super::Prove {}
}
