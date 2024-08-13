//! TLS Verifier state.

use mpz_core::hash::Hash;
use tls_core::key::PublicKey;
use tls_tee::TeeTlsFollower;
use tlsn_common::{
    mux::{MuxControl, MuxFuture},
    Context, DEAPThread, Io, OTSender,
};

/// TLS Verifier state.
pub trait VerifierState: sealed::Sealed {}

/// Initialized state.
pub struct Initialized;

opaque_debug::implement!(Initialized);

/// State after MPC setup has completed.
pub struct Setup {
    pub(crate) io: Io,
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,

    pub(crate) mpc_tls: TeeTlsFollower,
    pub(crate) ctx: Context,

    pub(crate) encoder_seed: [u8; 32],
}

/// State after the TLS connection has been closed.
pub struct Closed {
    pub(crate) io: Io,
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,

    pub(crate) ctx: Context,

    pub(crate) encoder_seed: [u8; 32],
    pub(crate) start_time: u64,
}

opaque_debug::implement!(Closed);

/// Notarizing state.
pub struct Notarize {
    pub(crate) io: Io,
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,

    pub(crate) ctx: Context,

    pub(crate) encoder_seed: [u8; 32],
    pub(crate) start_time: u64,
}

opaque_debug::implement!(Notarize);

impl From<Closed> for Notarize {
    fn from(value: Closed) -> Self {
        Self {
            io: value.io,
            mux_ctrl: value.mux_ctrl,
            mux_fut: value.mux_fut,
            ctx: value.ctx,
            encoder_seed: value.encoder_seed,
            start_time: value.start_time,
        }
    }
}

/// Verifying state.
pub struct Verify {
    pub(crate) io: Io,
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,
    pub(crate) ctx: Context,

    pub(crate) start_time: u64,
}

opaque_debug::implement!(Verify);

impl From<Closed> for Verify {
    fn from(value: Closed) -> Self {
        Self {
            io: value.io,
            mux_ctrl: value.mux_ctrl,
            mux_fut: value.mux_fut,
            ctx: value.ctx,
            start_time: value.start_time,
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
