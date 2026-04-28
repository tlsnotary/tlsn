//! TLS Verifier state.

use mpc_tls::SessionKeys;
use tlsn_core::{
    config::{prove::ProveRequest, tls_commit::TlsCommitRequest},
    connection::{HandshakeData, ServerName},
    transcript::{PartialTranscript, TlsTranscript},
};

use crate::{ProtocolConfig, deps::VerifierZk};

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
pub struct CommitAccepted<P: ProtocolConfig> {
    pub(crate) deps: <P as ProtocolConfig>::VerifierDeps,
}

impl<P: ProtocolConfig> std::fmt::Debug for CommitAccepted<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommitAccepted")
            .field("deps", &"{{ }}")
            .finish()
    }
}

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
impl<P: ProtocolConfig> VerifierState for CommitAccepted<P> {}
impl VerifierState for Committed {}
impl VerifierState for Verify {}

mod sealed {
    use crate::ProtocolConfig;

    pub trait Sealed {}
    impl Sealed for super::Initialized {}
    impl Sealed for super::CommitStart {}
    impl<P: ProtocolConfig> Sealed for super::CommitAccepted<P> {}
    impl Sealed for super::Committed {}
    impl Sealed for super::Verify {}
}
