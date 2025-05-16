//! TLS Verifier state.

use std::sync::Arc;

use crate::{Mpc, Zk};
use mpc_tls::{MpcTlsFollower, SessionKeys};
use mpz_common::{context::Multithread, Context};
use mpz_memory_core::correlated::Delta;
use tlsn_common::{
    mux::{MuxControl, MuxFuture},
    transcript::TranscriptRefs,
    zk_aes_ctr::ZkAesCtr,
};
use tlsn_core::connection::{ConnectionInfo, ServerEphemKey};
use tlsn_deap::Deap;
use tokio::sync::Mutex;

/// TLS Verifier state.
pub trait VerifierState: sealed::Sealed {}

/// Initialized state.
pub struct Initialized;

opaque_debug::implement!(Initialized);

/// State after setup has completed.
pub struct Setup {
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,
    pub(crate) mt: Multithread,
    pub(crate) delta: Delta,
    pub(crate) mpc_tls: MpcTlsFollower,
    pub(crate) zk_aes_ctr: ZkAesCtr,
    pub(crate) _keys: SessionKeys,
    pub(crate) vm: Arc<Mutex<Deap<Mpc, Zk>>>,
}

/// State after the TLS connection has been closed.
pub struct Closed {
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,
    pub(crate) mt: Multithread,
    pub(crate) delta: Delta,
    pub(crate) ctx: Context,
    pub(crate) keys: SessionKeys,
    pub(crate) vm: Zk,
    pub(crate) server_ephemeral_key: ServerEphemKey,
    pub(crate) connection_info: ConnectionInfo,
    pub(crate) transcript_refs: TranscriptRefs,
}

opaque_debug::implement!(Closed);

/// Notarizing state.
pub struct Notarize {
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,
    pub(crate) _mt: Multithread,
    pub(crate) delta: Delta,
    pub(crate) ctx: Context,
    pub(crate) _keys: SessionKeys,
    pub(crate) vm: Zk,
    pub(crate) server_ephemeral_key: ServerEphemKey,
    pub(crate) connection_info: ConnectionInfo,
    pub(crate) transcript_refs: TranscriptRefs,
}

opaque_debug::implement!(Notarize);

impl From<Closed> for Notarize {
    fn from(value: Closed) -> Self {
        Self {
            mux_ctrl: value.mux_ctrl,
            mux_fut: value.mux_fut,
            _mt: value.mt,
            delta: value.delta,
            ctx: value.ctx,
            _keys: value.keys,
            vm: value.vm,
            server_ephemeral_key: value.server_ephemeral_key,
            connection_info: value.connection_info,
            transcript_refs: value.transcript_refs,
        }
    }
}

/// Verifying state.
pub struct Verify {
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,
    pub(crate) _mt: Multithread,
    pub(crate) ctx: Context,
    pub(crate) _keys: SessionKeys,
    pub(crate) vm: Zk,
    pub(crate) server_ephemeral_key: ServerEphemKey,
    pub(crate) connection_info: ConnectionInfo,
    pub(crate) transcript_refs: TranscriptRefs,
}

opaque_debug::implement!(Verify);

impl From<Closed> for Verify {
    fn from(value: Closed) -> Self {
        Self {
            mux_ctrl: value.mux_ctrl,
            mux_fut: value.mux_fut,
            _mt: value.mt,
            ctx: value.ctx,
            _keys: value.keys,
            vm: value.vm,
            server_ephemeral_key: value.server_ephemeral_key,
            connection_info: value.connection_info,
            transcript_refs: value.transcript_refs,
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
