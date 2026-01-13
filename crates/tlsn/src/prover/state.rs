//! TLS prover states.

use std::sync::Arc;

use mpc_tls::{MpcTlsLeader, SessionKeys};
use mpz_common::Context;
use tlsn_core::{
    connection::ServerName,
    transcript::{TlsTranscript, Transcript},
};
use tlsn_deap::Deap;
use tokio::sync::Mutex;

use crate::{
    mpz::{ProverMpc, ProverZk},
    mux::MuxFuture,
};

/// Entry state
pub struct Initialized;

opaque_debug::implement!(Initialized);

/// State after the verifier has accepted the proposed TLS commitment protocol
/// configuration and preprocessing has completed.
pub struct CommitAccepted<Io> {
    pub(crate) mux_fut: MuxFuture<Io>,
    pub(crate) mpc_tls: MpcTlsLeader,
    pub(crate) keys: SessionKeys,
    pub(crate) vm: Arc<Mutex<Deap<ProverMpc, ProverZk>>>,
}

opaque_debug::implement!(CommitAccepted<Io>);

/// State after the TLS transcript has been committed.
pub struct Committed<Io> {
    pub(crate) mux_fut: MuxFuture<Io>,
    pub(crate) ctx: Context,
    pub(crate) vm: ProverZk,
    pub(crate) server_name: ServerName,
    pub(crate) keys: SessionKeys,
    pub(crate) tls_transcript: TlsTranscript,
    pub(crate) transcript: Transcript,
}

opaque_debug::implement!(Committed<Io>);

#[allow(missing_docs)]
pub trait ProverState: sealed::Sealed {}

impl ProverState for Initialized {}
impl<Io> ProverState for CommitAccepted<Io> {}
impl<Io> ProverState for Committed<Io> {}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Initialized {}
    impl<Io> Sealed for super::CommitAccepted<Io> {}
    impl<Io> Sealed for super::Committed<Io> {}
}
