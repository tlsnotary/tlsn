//! TLS prover states.

use futures_plex::DuplexStream;
use mpc_tls::SessionKeys;
use mpz_common::Context;
use tlsn_core::{
    config::tls_commit::{Mpc, Protocol, Proxy},
    connection::ServerName,
    transcript::{TlsTranscript, Transcript},
};

use crate::{
    Error, TlsOutput,
    deps::{MpcProverDeps, ProverZk, ProxyProverDeps},
    prover::{ProverControl, client::TlsClient},
};

/// Protocol-specific prover dependencies.
///
/// Binds a [`Protocol`] marker to its concrete dependency storage, so that a
/// prover in [`CommitAccepted<P>`] holds exactly the resources it needs for
/// that protocol — no runtime dispatch.
pub trait ProverProtocol: Protocol + sealed::Sealed {
    /// Protocol-specific prover dependencies.
    type Deps: Send + 'static;
}

impl ProverProtocol for Mpc {
    type Deps = MpcProverDeps;
}

impl ProverProtocol for Proxy {
    type Deps = ProxyProverDeps;
}

/// Entry state
pub struct Initialized;

opaque_debug::implement!(Initialized);

/// State after the verifier has accepted the proposed TLS commitment protocol
/// configuration and preprocessing has completed.
pub struct CommitAccepted<P: ProverProtocol> {
    pub(crate) deps: P::Deps,
}

impl<P: ProverProtocol> std::fmt::Debug for CommitAccepted<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CommitAccepted<{}> {{ ... }}", std::any::type_name::<P>())
    }
}

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
impl<P: ProverProtocol> ProverState for CommitAccepted<P> {}
impl<S> ProverState for Connected<S> {}
impl ProverState for Committed {}

mod sealed {
    use tlsn_core::config::tls_commit::{Mpc, Proxy};

    pub trait Sealed {}
    impl Sealed for super::Initialized {}
    impl<P: super::ProverProtocol> Sealed for super::CommitAccepted<P> {}
    impl<S> Sealed for super::Connected<S> {}
    impl Sealed for super::Committed {}

    impl Sealed for Mpc {}
    impl Sealed for Proxy {}
}
