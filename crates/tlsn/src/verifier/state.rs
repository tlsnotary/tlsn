//! TLS Verifier state.

use mpc_tls::SessionKeys;
use tlsn_core::{
    config::{prove::ProveRequest, tls_commit::TlsCommitRequest},
    connection::{HandshakeData, ServerName},
    transcript::{PartialTranscript, TlsTranscript},
};

use crate::deps::VerifierZk;

/// TLS Verifier state.
pub trait VerifierState: sealed::Sealed {}

/// Initialized state.
pub struct Initialized;

opaque_debug::implement!(Initialized);

/// State after receiving protocol configuration from the prover.
pub struct CommitStart {
    pub(crate) request: TlsCommitRequest,
}

opaque_debug::implement!(CommitStart);

/// State after accepting the proposed TLS commitment protocol configuration and
/// performing preprocessing.
pub struct CommitAccepted<D> {
    pub(crate) deps: D,
}

opaque_debug::implement!(CommitAccepted<D>);

/// State after the TLS transcript has been committed.
pub struct Committed {
    pub(crate) vm: VerifierZk,
    pub(crate) keys: SessionKeys,
    pub(crate) tls_transcript: TlsTranscript,
}

opaque_debug::implement!(Committed);

/// State after receiving a proving request.
pub struct Verify {
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
impl<D> VerifierState for CommitAccepted<D> {}
impl VerifierState for Committed {}
impl VerifierState for Verify {}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Initialized {}
    impl Sealed for super::CommitStart {}
    impl<D> Sealed for super::CommitAccepted<D> {}
    impl Sealed for super::Committed {}
    impl Sealed for super::Verify {}
}
