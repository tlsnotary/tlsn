//! TLS Verifier state.

use std::sync::Arc;

use crate::mux::MuxFuture;
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
pub struct CommitStart<Io> {
    pub(crate) mux_fut: MuxFuture<Io>,
    pub(crate) ctx: Context,
    pub(crate) request: TlsCommitRequest,
}

opaque_debug::implement!(CommitStart<Io>);

/// State after accepting the proposed TLS commitment protocol configuration and
/// performing preprocessing.
pub struct CommitAccepted<Io> {
    pub(crate) mux_fut: MuxFuture<Io>,
    pub(crate) mpc_tls: MpcTlsFollower,
    pub(crate) keys: SessionKeys,
    pub(crate) vm: Arc<Mutex<Deap<VerifierMpc, VerifierZk>>>,
}

opaque_debug::implement!(CommitAccepted<Io>);

/// State after the TLS transcript has been committed.
pub struct Committed<Io> {
    pub(crate) mux_fut: MuxFuture<Io>,
    pub(crate) ctx: Context,
    pub(crate) vm: VerifierZk,
    pub(crate) keys: SessionKeys,
    pub(crate) tls_transcript: TlsTranscript,
}

opaque_debug::implement!(Committed<Io>);

/// State after receiving a proving request.
pub struct Verify<Io> {
    pub(crate) mux_fut: MuxFuture<Io>,
    pub(crate) ctx: Context,
    pub(crate) vm: VerifierZk,
    pub(crate) keys: SessionKeys,
    pub(crate) tls_transcript: TlsTranscript,
    pub(crate) request: ProveRequest,
    pub(crate) handshake: Option<(ServerName, HandshakeData)>,
    pub(crate) transcript: Option<PartialTranscript>,
}

opaque_debug::implement!(Verify<Io>);

impl VerifierState for Initialized {}
impl<Io> VerifierState for CommitStart<Io> {}
impl<Io> VerifierState for CommitAccepted<Io> {}
impl<Io> VerifierState for Committed<Io> {}
impl<Io> VerifierState for Verify<Io> {}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Initialized {}
    impl<Io> Sealed for super::CommitStart<Io> {}
    impl<Io> Sealed for super::CommitAccepted<Io> {}
    impl<Io> Sealed for super::Committed<Io> {}
    impl<Io> Sealed for super::Verify<Io> {}
}
