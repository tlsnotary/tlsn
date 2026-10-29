use std::{
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};

use futures::{AsyncWriteExt, task::waker};
use mpz_common::Context as MpzContext;
use tlsn_core::connection::ServerName;

use super::harness::WakeCounter;
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
    wants_write: Arc<AtomicBool>,
    written: Arc<Mutex<Vec<u8>>>,
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
        false
    }

    fn wants_write(&self) -> bool {
        self.wants_write.load(Ordering::Relaxed)
    }

    fn read(&mut self, _buf: &mut [u8]) -> Result<usize, Self::Error> {
        Ok(0)
    }

    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.written.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
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

/// Buffered plaintext must not re-arm the waker while the TLS client cannot
/// accept it. Re-arming without progress is what turned this into a busy loop
/// while MPC work was pending.
#[test]
fn blocked_plaintext_does_not_self_wake() {
    let (client_io, mut app_io) = futures_plex::duplex(BUF_CAP);
    let (client_to_server, server_to_client) = futures_plex::duplex(BUF_CAP);
    let (server_socket, _server_peer) = futures_plex::duplex(BUF_CAP);

    let wants_write = Arc::new(AtomicBool::new(false));
    let written = Arc::new(Mutex::new(Vec::new()));
    let decrypt = Arc::new(DecryptState::new());

    let tls_client = MockTlsClient {
        wants_write: wants_write.clone(),
        written: written.clone(),
        decrypt: decrypt.clone(),
    };

    let mut state = state::Connected {
        server_name: ServerName::Dns("example.com".try_into().unwrap()),
        tls_client: Box::new(tls_client),
        control: ProverControl { decrypt },
        client_io,
        output: None,
        server_socket,
        client_to_server,
        server_to_client,
        client_closed: false,
        server_closed: false,
    };

    futures::executor::block_on(app_io.write_all(b"hello")).unwrap();

    let wake_counter = WakeCounter::new();
    let waker = waker(wake_counter.clone());
    let mut cx = Context::from_waker(&waker);

    // The client cannot accept plaintext yet: the data stays queued and
    // the waker must not be re-armed.
    {
        let mut proj = Pin::new(&mut state).project();
        Prover::<state::Connected<futures_plex::DuplexStream>>::io_to_tls_client(
            &mut proj, &mut cx,
        )
        .unwrap();
    }
    assert_eq!(
        wake_counter.take(),
        0,
        "blocked plaintext must not self-wake"
    );
    assert!(written.lock().unwrap().is_empty());

    // Once the client is writable, the queued plaintext is consumed.
    wants_write.store(true, Ordering::Relaxed);
    {
        let mut proj = Pin::new(&mut state).project();
        Prover::<state::Connected<futures_plex::DuplexStream>>::io_to_tls_client(
            &mut proj, &mut cx,
        )
        .unwrap();
    }
    assert_eq!(written.lock().unwrap().as_slice(), b"hello");
}
