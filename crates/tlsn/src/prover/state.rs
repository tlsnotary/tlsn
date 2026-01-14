//! TLS prover states.

use std::sync::Arc;

use mpc_tls::{MpcTlsLeader, SessionKeys};
use tlsn_core::{
    connection::ServerName,
    transcript::{TlsTranscript, Transcript},
};
use tlsn_deap::Deap;
use tokio::sync::Mutex;

use crate::mpz::{ProverMpc, ProverZk};

/// Entry state
pub struct Initialized;

opaque_debug::implement!(Initialized);

/// State after the verifier has accepted the proposed TLS commitment protocol
/// configuration and preprocessing has completed.
pub struct CommitAccepted {
    pub(crate) mpc_tls: MpcTlsLeader,
    pub(crate) keys: SessionKeys,
    pub(crate) vm: Arc<Mutex<Deap<ProverMpc, ProverZk>>>,
}

opaque_debug::implement!(CommitAccepted);

/// State after the TLS transcript has been committed.
pub struct Committed {
    pub(crate) vm: ProverZk,
    pub(crate) server_name: ServerName,
    pub(crate) keys: SessionKeys,
    pub(crate) tls_transcript: TlsTranscript,
    pub(crate) transcript: Transcript,
}

opaque_debug::implement!(Committed);

#[allow(missing_docs)]
pub trait ProverState: sealed::Sealed {}

impl ProverState for Initialized {}
impl ProverState for CommitAccepted {}
impl ProverState for Committed {}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Initialized {}
    impl Sealed for super::CommitAccepted {}
    impl Sealed for super::Committed {}
}
