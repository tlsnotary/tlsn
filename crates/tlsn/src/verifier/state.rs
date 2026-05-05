//! TLS Verifier state.

use std::marker::PhantomData;

use mpc_tls::SessionKeys;
use tlsn_core::{
    config::prove::ProveRequest,
    connection::{HandshakeData, ServerName},
    transcript::{PartialTranscript, TlsTranscript},
};

use tlsn_core::config::tls_commit::TlsCommitConfig;

use crate::deps::{VerifierDeps, VerifierZk};

/// TLS Verifier state.
pub trait VerifierState: sealed::Sealed {}

/// Initialized state.
pub struct Initialized;

opaque_debug::implement!(Initialized);

/// State after receiving protocol configuration from the prover.
pub struct CommitStart<C> {
    pub(crate) config: TlsCommitConfig,
    pub(crate) _pd: PhantomData<C>,
}

impl<C> std::fmt::Debug for CommitStart<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommitStart").finish_non_exhaustive()
    }
}

/// State after accepting the proposed TLS commitment protocol configuration and
/// performing preprocessing.
pub struct CommitAccepted<C> {
    pub(crate) deps: VerifierDeps,
    pub(crate) _pd: PhantomData<C>,
}

impl<C> std::fmt::Debug for CommitAccepted<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommitAccepted").finish_non_exhaustive()
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
impl<C> VerifierState for CommitStart<C> {}
impl<C> VerifierState for CommitAccepted<C> {}
impl VerifierState for Committed {}
impl VerifierState for Verify {}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Initialized {}
    impl<C> Sealed for super::CommitStart<C> {}
    impl<C> Sealed for super::CommitAccepted<C> {}
    impl Sealed for super::Committed {}
    impl Sealed for super::Verify {}
}
