//! TLS Verifier state.

use mpz_core::hash::Hash;
use tls_core::key::PublicKey;
use tls_mpc::MpcTlsFollower;
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
    pub(crate) start_time: u64,
    pub(crate) server_ephemeral_key: PublicKey,
    pub(crate) handshake_commitment: Hash,
    pub(crate) sent_len: usize,
    pub(crate) recv_len: usize,
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
    pub(crate) start_time: u64,
    pub(crate) server_ephemeral_key: PublicKey,
    pub(crate) handshake_commitment: Hash,
    pub(crate) sent_len: usize,
    pub(crate) recv_len: usize,
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
            start_time: value.start_time,
            server_ephemeral_key: value.server_ephemeral_key,
            handshake_commitment: value.handshake_commitment,
            sent_len: value.sent_len,
            recv_len: value.recv_len,
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

    pub(crate) start_time: u64,
    pub(crate) server_ephemeral_key: PublicKey,
    pub(crate) handshake_commitment: Hash,
    pub(crate) sent_len: usize,
    pub(crate) recv_len: usize,
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
            start_time: value.start_time,
            server_ephemeral_key: value.server_ephemeral_key,
            handshake_commitment: value.handshake_commitment,
            sent_len: value.sent_len,
            recv_len: value.recv_len,
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
