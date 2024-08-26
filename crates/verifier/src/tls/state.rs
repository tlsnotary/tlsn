//! TLS Verifier state.

use tls_tee::TeeTlsFollower;
use tlsn_common::{
    mux::{MuxControl, MuxFuture},
    Io,
};

/// TLS Verifier state.
pub trait VerifierState: sealed::Sealed {}

/// Initialized state.
pub struct Initialized;

opaque_debug::implement!(Initialized);

/// State after TEE setup has completed.
pub struct Setup {
    pub(crate) io: Io,
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,

    pub(crate) tee_tls: TeeTlsFollower,
}

/// State after the TLS connection has been closed.
pub struct Closed {
    pub(crate) io: Io,
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,
    pub(crate) response_data: String,
    pub(crate) request_data: String,
}

opaque_debug::implement!(Closed);

/// Notarizing state.
pub struct Notarize {
    pub(crate) io: Io,
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,
    pub(crate) response_data: String,
    pub(crate) request_data: String,
}

opaque_debug::implement!(Notarize);

impl From<Closed> for Notarize {
    fn from(value: Closed) -> Self {
        Self {
            response_data: value.response_data,
            request_data: value.request_data,
            io: value.io,
            mux_ctrl: value.mux_ctrl,
            mux_fut: value.mux_fut,
        }
    }
}

/// Verifying state.
pub struct Verify {
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,
}

opaque_debug::implement!(Verify);

impl From<Closed> for Verify {
    fn from(value: Closed) -> Self {
        Self {
            mux_ctrl: value.mux_ctrl,
            mux_fut: value.mux_fut,
        }
    }
}

impl VerifierState for Initialized {}
impl VerifierState for Setup {}
impl VerifierState for Closed {}
impl VerifierState for Notarize {}
impl VerifierState for Verify {}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Initialized {}
    impl Sealed for super::Setup {}
    impl Sealed for super::Closed {}
    impl Sealed for super::Notarize {}
    impl Sealed for super::Verify {}
}
