//! TLS prover states.

use futures_plex::DuplexStream;
use mpc_tls::SessionKeys;
use mpz_common::Context;
use tlsn_core::{
    connection::ServerName,
    transcript::{TlsTranscript, Transcript},
};

use crate::{
    Error, TlsOutput,
    deps::ProverZk,
    prover::{ProverControl, client::TlsClient},
};

/// Entry state
pub struct Initialized;

opaque_debug::implement!(Initialized);

/// State after the verifier has accepted the proposed TLS commitment protocol
/// configuration and preprocessing has completed.
pub struct CommitAccepted<D> {
    pub(crate) deps: D,
}

opaque_debug::implement!(CommitAccepted<D>);

pin_project_lite::pin_project! {
    /// State during the MPC-TLS connection.
    #[project = ConnectedProj]
    pub struct Connected<S> {
        pub(crate) server_name: ServerName,
        pub(crate) tls_client: Box<dyn TlsClient<Error = Error> + Send>,
        pub(crate) control: ProverControl,
        #[pin]
        pub(crate) client_io: DuplexStream,
        pub(crate) output: Option<(Context, ProverZk, TlsOutput)>,
        #[pin]
        pub(crate) server_socket: S,
        #[pin]
        pub(crate) client_to_server: DuplexStream,
        #[pin]
        pub(crate) server_to_client: DuplexStream,
        pub(crate) client_closed: bool,
        pub(crate) server_closed: bool
    }
}

opaque_debug::implement!(Connected<S>);

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
impl<D> ProverState for CommitAccepted<D> {}
impl<S> ProverState for Connected<S> {}
impl ProverState for Committed {}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Initialized {}
    impl<D> Sealed for super::CommitAccepted<D> {}
    impl<S> Sealed for super::Connected<S> {}
    impl Sealed for super::Committed {}
}
