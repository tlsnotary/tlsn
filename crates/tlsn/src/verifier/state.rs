//! TLS Verifier state.

use mpc_tls::SessionKeys;
use tlsn_core::{
    config::prove::ProveRequest,
    connection::{HandshakeData, ServerName},
    transcript::{PartialTranscript, TlsTranscript},
};

use crate::{
    ProtocolConfig, Verify as VerifyZst,
    deps::{ProtocolDeps, VerifierZk},
};

/// TLS Verifier state.
pub trait VerifierState: sealed::Sealed {}

/// Initialized state.
pub struct Initialized;

opaque_debug::implement!(Initialized);

/// State after receiving protocol configuration from the prover.
pub struct CommitStart<P: ProtocolConfig<VerifyZst>> {
    pub(crate) config: P,
}

impl<P: ProtocolConfig<VerifyZst>> std::fmt::Debug for CommitStart<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommitAccepted")
            .field("deps", &"{{ }}")
            .finish()
    }
}

/// State after accepting the proposed TLS commitment protocol configuration and
/// performing preprocessing.
pub struct CommitAccepted<P: ProtocolConfig<VerifyZst>> {
    pub(crate) deps: <P as ProtocolDeps<VerifyZst>>::Deps,
}

impl<P: ProtocolConfig<VerifyZst>> std::fmt::Debug for CommitAccepted<P> {
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
impl<P: ProtocolConfig<VerifyZst>> VerifierState for CommitStart<P> {}
impl<P: ProtocolConfig<VerifyZst>> VerifierState for CommitAccepted<P> {}
impl VerifierState for Committed {}
impl VerifierState for Verify {}

mod sealed {
    use crate::{ProtocolConfig, Verify as VerifyZst};

    pub trait Sealed {}
    impl Sealed for super::Initialized {}
    impl<P: ProtocolConfig<VerifyZst>> Sealed for super::CommitStart<P> {}
    impl<P: ProtocolConfig<VerifyZst>> Sealed for super::CommitAccepted<P> {}
    impl Sealed for super::Committed {}
    impl Sealed for super::Verify {}
}
