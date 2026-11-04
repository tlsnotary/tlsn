//! TLS prover states.

use std::marker::PhantomData;

use futures_plex::DuplexStream;
use mpc_tls::SessionKeys;
use mpz_common::Context;
use tlsn_core::{
    connection::ServerName,
    transcript::{TlsTranscript, Transcript},
};

use crate::{
    Error, TlsOutput,
    deps::{ProverDeps, ProverZk},
    prover::{ProverControl, client::TlsClient, close::CloseState},
};

/// Entry state
pub struct Initialized;

opaque_debug::implement!(Initialized);

/// State after the verifier has accepted the proposed TLS commitment protocol
/// configuration and preprocessing has completed.
#[derive(Debug)]
pub struct CommitAccepted<P> {
    pub(crate) deps: ProverDeps,
    pub(crate) _pd: PhantomData<P>,
}

pin_project_lite::pin_project! {
    /// State during the MPC-TLS connection.
    ///
    /// TLS bytes reach the peer in two hops: the client fills a staging
    /// channel and the prover forwards from there to the transport. Records the
    /// client produced can therefore be in flight between the two, so the
    /// transport must not be closed until that channel is both closed and
    /// drained.
    ///
    /// The field comments below are plain comments because this struct is
    /// expanded by `pin_project_lite`, which rejects attributes other than
    /// `#[pin]` on fields; see taiki-e/pin-project-lite#3.
    #[project = ConnectedProj]
    pub struct Connected<S> {
        pub(crate) server_name: ServerName,
        pub(crate) tls_client: Box<dyn TlsClient<Error = Error> + Send>,
        pub(crate) control: ProverControl,
        #[pin]
        pub(crate) client_io: DuplexStream,
        pub(crate) output: Option<(Context, ProverZk, TlsOutput)>,
        // Transport carrying TLS bytes towards the peer. In proxy mode this is
        // the mux stream to the verifier, which relays it to the server.
        #[pin]
        pub(crate) server_socket: S,
        // The client's end of the staging channel. The TLS client writes its
        // records here; they surface on `socket_end` for forwarding to
        // `server_socket`. Bytes arriving from the server are written to
        // `socket_end` and read from here.
        #[pin]
        pub(crate) client_end: DuplexStream,
        // The socket's end of the same channel: outbound bytes written to
        // `client_end` surface here and are forwarded to `server_socket`, and
        // inbound bytes read from `server_socket` are staged here for the
        // client to read.
        #[pin]
        pub(crate) socket_end: DuplexStream,
        // Per-direction close state at the transport layer.
        pub(crate) close: CloseState,
        // Whether `client_end` has been closed for writing. That marks the end
        // of the TLS output stream: the channel only reports end-of-file once
        // every byte has been read out, which is what makes it a reliable
        // "everything has been handed to the transport" signal.
        pub(crate) pipe_closed: bool,
        // Whether those bytes have all been forwarded to `server_socket`.
        pub(crate) pipe_drained: bool
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
impl<P> ProverState for CommitAccepted<P> {}
impl<S> ProverState for Connected<S> {}
impl ProverState for Committed {}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Initialized {}
    impl<P> Sealed for super::CommitAccepted<P> {}
    impl<S> Sealed for super::Connected<S> {}
    impl Sealed for super::Committed {}
}
