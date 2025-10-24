//! TLS Verifier state.

use std::sync::Arc;

use crate::mux::{MuxControl, MuxFuture};
use mpc_tls::{MpcTlsFollower, SessionKeys};
use mpz_common::Context;
use tlsn_core::{
    config::{prove::ProveRequest, tls_commit::TlsCommitRequest},
    connection::{HandshakeData, ServerName},
    transcript::{PartialTranscript, TlsTranscript},
};
use tlsn_deap::Deap;
use tokio::sync::Mutex;

use crate::mpz::{VerifierMpc, VerifierZk};

/// TLS Verifier state.
pub trait VerifierState: sealed::Sealed {}

/// Initialized state.
pub struct Initialized;

opaque_debug::implement!(Initialized);

/// State after receiving protocol configuration from the prover.
pub struct CommitStart {
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,
    pub(crate) ctx: Context,
    pub(crate) request: TlsCommitRequest,
}

opaque_debug::implement!(CommitStart);

/// State after accepting the proposed TLS commitment protocol configuration and
/// performing preprocessing.
pub struct CommitAccepted {
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,
    pub(crate) mpc_tls: MpcTlsFollower,
    pub(crate) keys: SessionKeys,
    pub(crate) vm: Arc<Mutex<Deap<VerifierMpc, VerifierZk>>>,
}

opaque_debug::implement!(CommitAccepted);

/// State after the TLS transcript has been committed.
pub struct Committed {
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,
    pub(crate) ctx: Context,
    pub(crate) vm: VerifierZk,
    pub(crate) keys: SessionKeys,
    pub(crate) tls_transcript: TlsTranscript,
}

opaque_debug::implement!(Committed);

/// State after receiving a proving request.
pub struct Verify {
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,
    pub(crate) ctx: Context,
    pub(crate) vm: VerifierZk,
    pub(crate) keys: SessionKeys,
    pub(crate) tls_transcript: TlsTranscript,
    pub(crate) request: ProveRequest,
    pub(crate) handshake: Option<(ServerName, HandshakeData)>,
    pub(crate) transcript: Option<PartialTranscript>,
}

opaque_debug::implement!(Verify);

impl VerifierState for Initialized {}
impl VerifierState for CommitStart {}
impl VerifierState for CommitAccepted {}
impl VerifierState for Committed {}
impl VerifierState for Verify {}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Initialized {}
    impl Sealed for super::CommitStart {}
    impl Sealed for super::CommitAccepted {}
    impl Sealed for super::Committed {}
    impl Sealed for super::Verify {}
}
