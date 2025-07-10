//! TLS prover states.

use std::sync::Arc;

use mpc_tls::{MpcTlsLeader, SessionKeys};
use mpz_common::Context;
use tlsn_core::transcript::{TlsTranscript, Transcript};
use tlsn_deap::Deap;
use tokio::sync::Mutex;

use crate::{
    mux::{MuxControl, MuxFuture},
    prover::{Mpc, Zk},
    zk_aes_ctr::ZkAesCtr,
};

/// Entry state
pub struct Initialized;

opaque_debug::implement!(Initialized);

/// State after MPC setup has completed.
pub struct Setup {
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,
    pub(crate) mpc_tls: MpcTlsLeader,
    pub(crate) zk_aes_ctr_sent: ZkAesCtr,
    pub(crate) zk_aes_ctr_recv: ZkAesCtr,
    pub(crate) keys: SessionKeys,
    pub(crate) vm: Arc<Mutex<Deap<Mpc, Zk>>>,
}

opaque_debug::implement!(Setup);

/// State after the TLS connection has been closed.
pub struct Closed {
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,
    pub(crate) ctx: Context,
    pub(crate) vm: Zk,
    pub(crate) tls_transcript: TlsTranscript,
    pub(crate) transcript: Transcript,
    pub(crate) zk_aes_ctr_sent: ZkAesCtr,
    pub(crate) zk_aes_ctr_recv: ZkAesCtr,
}

opaque_debug::implement!(Closed);

#[allow(missing_docs)]
pub trait ProverState: sealed::Sealed {}

impl ProverState for Initialized {}
impl ProverState for Setup {}
impl ProverState for Closed {}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Initialized {}
    impl Sealed for super::Setup {}
    impl Sealed for super::Closed {}
}
