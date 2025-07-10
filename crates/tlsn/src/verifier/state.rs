//! TLS Verifier state.

use std::sync::Arc;

use crate::{
    mux::{MuxControl, MuxFuture},
    zk_aes_ctr::ZkAesCtr,
};
use mpc_tls::{MpcTlsFollower, SessionKeys};
use mpz_common::Context;
use mpz_memory_core::correlated::Delta;
use tlsn_core::transcript::TlsTranscript;
use tlsn_deap::Deap;
use tokio::sync::Mutex;

use crate::verifier::{Mpc, Zk};

/// TLS Verifier state.
pub trait VerifierState: sealed::Sealed {}

/// Initialized state.
pub struct Initialized;

opaque_debug::implement!(Initialized);

/// State after setup has completed.
pub struct Setup {
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,
    pub(crate) delta: Delta,
    pub(crate) mpc_tls: MpcTlsFollower,
    pub(crate) zk_aes_ctr_sent: ZkAesCtr,
    pub(crate) zk_aes_ctr_recv: ZkAesCtr,
    pub(crate) keys: SessionKeys,
    pub(crate) vm: Arc<Mutex<Deap<Mpc, Zk>>>,
}

/// State after the TLS connection has been closed.
pub struct Committed {
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,
    pub(crate) delta: Delta,
    pub(crate) ctx: Context,
    pub(crate) vm: Zk,
    pub(crate) tls_transcript: TlsTranscript,
    pub(crate) zk_aes_ctr_sent: ZkAesCtr,
    pub(crate) zk_aes_ctr_recv: ZkAesCtr,
    pub(crate) keys: SessionKeys,
}

opaque_debug::implement!(Committed);

impl VerifierState for Initialized {}
impl VerifierState for Setup {}
impl VerifierState for Committed {}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Initialized {}
    impl Sealed for super::Setup {}
    impl Sealed for super::Committed {}
}
