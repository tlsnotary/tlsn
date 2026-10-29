use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures::task::noop_waker;
use mpz_common::Context as MpzContext;
use tlsn_core::connection::ServerName;

use crate::{
    Error, TlsOutput,
    deps::ProverZk,
    prover::{
        BUF_CAP, Prover, ProverControl,
        client::{DecryptState, TlsClient},
        state,
    },
};

struct MockTlsClient {
    decrypt: Arc<DecryptState>,
}

impl TlsClient for MockTlsClient {
    type Error = Error;

    fn wants_read_tls(&self) -> bool {
        false
    }

    fn wants_write_tls(&self) -> bool {
        false
    }

    fn read_tls(&mut self, _buf: &[u8]) -> Result<usize, Self::Error> {
        Ok(0)
    }

    fn write_tls(&mut self, _buf: &mut [u8]) -> Result<usize, Self::Error> {
        Ok(0)
    }

    fn wants_read(&self) -> bool {
        true
    }

    fn wants_write(&self) -> bool {
        false
    }

    fn read(&mut self, _buf: &mut [u8]) -> Result<usize, Self::Error> {
        Ok(0)
    }

    fn write(&mut self, _buf: &[u8]) -> Result<usize, Self::Error> {
        Ok(0)
    }

    fn client_close(&mut self) {}

    fn server_close(&mut self) {}

    fn decrypt(&self) -> Arc<DecryptState> {
        self.decrypt.clone()
    }

    fn poll(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(MpzContext, ProverZk, TlsOutput), Self::Error>> {
        Poll::Pending
    }
}

/// If the application drops its side while decrypted plaintext is still
/// pending, the prover must terminate instead of silently ignoring the
/// closed channel. Otherwise it can wait forever for a reader that is gone.
#[test]
fn abandoned_client_with_pending_plaintext_terminates() {
    let (client_io, app_io) = futures_plex::duplex(BUF_CAP);
    let (client_to_server, server_to_client) = futures_plex::duplex(BUF_CAP);
    let (server_socket, _server_peer) = futures_plex::duplex(BUF_CAP);

    let decrypt = Arc::new(DecryptState::new());
    let mut state = state::Connected {
        server_name: ServerName::Dns("example.com".try_into().unwrap()),
        tls_client: Box::new(MockTlsClient {
            decrypt: decrypt.clone(),
        }),
        control: ProverControl { decrypt },
        client_io,
        output: None,
        server_socket,
        client_to_server,
        server_to_client,
        client_closed: false,
        server_closed: false,
    };

    drop(app_io);

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    let mut proj = Pin::new(&mut state).project();
    let result = Prover::<state::Connected<futures_plex::DuplexStream>>::io_from_tls_client(
        &mut proj, &mut cx,
    );

    assert!(
        result.is_err(),
        "closed client_io with pending plaintext must terminate"
    );
}
