//! TLS prover states.

use std::sync::Arc;

use futures_plex::DuplexStream;
use mpc_tls::{LeaderCtrl, MpcTlsLeader, SessionKeys};
use mpz_common::Context;
use tlsn_core::transcript::{TlsTranscript, Transcript};
use tlsn_deap::Deap;
use tokio::sync::Mutex;

use crate::{
    commit::transcript::TranscriptRefs,
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

/// State during the MPC-TLS connection.
pub struct Connected {
    pub(crate) mpc_ctrl: LeaderCtrl,
    pub(crate) client_handle: DuplexStream,
    pub(crate) server_handle: DuplexStream,
}

opaque_debug::implement!(Connected);

/// State after the TLS connection has been committed and closed.
pub struct Committed {
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,
    pub(crate) ctx: Context,
    pub(crate) vm: Zk,
    pub(crate) tls_transcript: TlsTranscript,
    pub(crate) transcript: Transcript,
    pub(crate) transcript_refs: TranscriptRefs,
}

opaque_debug::implement!(Committed);

#[allow(missing_docs)]
pub trait ProverState: sealed::Sealed {}

impl ProverState for Initialized {}
impl ProverState for Setup {}
impl ProverState for Connected {}
impl ProverState for Committed {}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Initialized {}
    impl Sealed for super::Setup {}
    impl Sealed for super::Connected {}
    impl Sealed for super::Committed {}
}
