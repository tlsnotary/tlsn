//! TLS Verifier state.

use tls_mpc::MpcTlsFollower;
use tlsn_common::{
    mux::{MuxControl, MuxFuture},
    Context, DEAPThread, Io, OTSender,
};
use tlsn_core::connection::{ConnectionInfo, ServerEphemKey};

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

    pub(crate) mpc_tls: MpcTlsFollower,
    pub(crate) vm: DEAPThread,
    pub(crate) ot_send: OTSender,
    pub(crate) ctx: Context,

    pub(crate) encoder_seed: [u8; 32],
}

/// State after the TLS connection has been closed.
pub struct Closed {
    pub(crate) io: Io,
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,

    pub(crate) vm: DEAPThread,
    pub(crate) ot_send: OTSender,
    pub(crate) ctx: Context,

    pub(crate) encoder_seed: [u8; 32],
    pub(crate) server_ephemeral_key: ServerEphemKey,
    pub(crate) connection_info: ConnectionInfo,
}

opaque_debug::implement!(Closed);

/// Notarizing state.
pub struct Notarize {
    pub(crate) io: Io,
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,

    pub(crate) vm: DEAPThread,
    pub(crate) ot_send: OTSender,
    pub(crate) ctx: Context,

    pub(crate) encoder_seed: [u8; 32],
    pub(crate) server_ephemeral_key: ServerEphemKey,
    pub(crate) connection_info: ConnectionInfo,
}

opaque_debug::implement!(Notarize);

impl From<Closed> for Notarize {
    fn from(value: Closed) -> Self {
        Self {
            io: value.io,
            mux_ctrl: value.mux_ctrl,
            mux_fut: value.mux_fut,
            vm: value.vm,
            ot_send: value.ot_send,
            ctx: value.ctx,
            encoder_seed: value.encoder_seed,
            server_ephemeral_key: value.server_ephemeral_key,
            connection_info: value.connection_info,
        }
    }
}

/// Verifying state.
pub struct Verify {
    pub(crate) io: Io,
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,

    pub(crate) vm: DEAPThread,
    pub(crate) ot_send: OTSender,
    pub(crate) ctx: Context,

    pub(crate) server_ephemeral_key: ServerEphemKey,
    pub(crate) connection_info: ConnectionInfo,
}

opaque_debug::implement!(Verify);

impl From<Closed> for Verify {
    fn from(value: Closed) -> Self {
        Self {
            io: value.io,
            mux_ctrl: value.mux_ctrl,
            mux_fut: value.mux_fut,
            vm: value.vm,
            ot_send: value.ot_send,
            ctx: value.ctx,
            server_ephemeral_key: value.server_ephemeral_key,
            connection_info: value.connection_info,
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
