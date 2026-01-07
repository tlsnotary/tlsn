//! TLS prover states.

use std::sync::Arc;

use futures_plex::DuplexStream;
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
    mux::{MuxControl, MuxFuture},
    prover::{
        ProverError,
        client::{TlsClient, TlsOutput},
    },
};

/// Entry state
pub struct Initialized;

opaque_debug::implement!(Initialized);

/// State after the verifier has accepted the proposed TLS commitment protocol
/// configuration and preprocessing has completed.
pub struct CommitAccepted {
    pub(crate) verifier_io: Option<DuplexStream>,
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,
    pub(crate) mpc_tls: MpcTlsLeader,
    pub(crate) keys: SessionKeys,
    pub(crate) vm: Arc<Mutex<Deap<ProverMpc, ProverZk>>>,
}

opaque_debug::implement!(CommitAccepted);

/// State when the TLS client has been setup.
pub struct Setup {
    pub(crate) verifier_io: Option<DuplexStream>,
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,
    pub(crate) server_name: ServerName,
    pub(crate) tls_client: Box<dyn TlsClient<Error = ProverError> + Send>,
    pub(crate) client_io: DuplexStream,
}

opaque_debug::implement!(Setup);

pin_project_lite::pin_project! {
    /// State during the MPC-TLS connection.
    #[project = ConnectedProj]
    pub struct Connected<S, T> {
        #[pin]
        pub(crate) verifier_io: Option<DuplexStream>,
        pub(crate) mux_ctrl: MuxControl,
        pub(crate) mux_fut: MuxFuture,
        pub(crate) server_name: ServerName,
        pub(crate) tls_client: Box<dyn TlsClient<Error = ProverError> + Send>,
        #[pin]
        pub(crate) client_io: DuplexStream,
        pub(crate) output: Option<TlsOutput>,
        #[pin]
        pub(crate) server_socket: S,
        #[pin]
        pub(crate) verifier_socket: T,
        #[pin]
        pub(crate) tls_client_to_server_buf: DuplexStream,
        #[pin]
        pub(crate) server_to_tls_client_buf: DuplexStream,
        pub(crate) client_closed: bool,
        pub(crate) server_closed: bool
    }
}

opaque_debug::implement!(Connected<S, T>);

/// State after the TLS transcript has been committed.
pub struct Committed {
    pub(crate) verifier_io: Option<DuplexStream>,
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,
    pub(crate) ctx: Context,
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
impl ProverState for Setup {}
impl<S, T> ProverState for Connected<S, T> {}
impl ProverState for Committed {}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Initialized {}
    impl Sealed for super::CommitAccepted {}
    impl Sealed for super::Setup {}
    impl<S, T> Sealed for super::Connected<S, T> {}
    impl Sealed for super::Committed {}
}
