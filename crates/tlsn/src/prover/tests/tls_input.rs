use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
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
    decrypt: Arc<DecryptState>,
    read_tls_calls: Arc<AtomicUsize>,
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
        self.read_tls_calls.fetch_add(1, Ordering::Relaxed);
        Ok(0)
    }

    fn write_tls(&mut self, _buf: &mut [u8]) -> Result<usize, Self::Error> {
        Ok(0)
    }

    fn wants_read(&self) -> bool {
        false
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

/// Buffered TLS input must not re-arm the waker while the client cannot
/// consume it. The current code wakes unconditionally in that branch, which
/// turns every poll into a busy loop while MPC work is pending.
#[test]
fn buffered_tls_input_does_not_self_wake() {
    let (client_io, _app_io) = futures_plex::duplex(BUF_CAP);
    let (client_to_server, server_to_client) = futures_plex::duplex(BUF_CAP);
    let (server_socket, mut server_peer) = futures_plex::duplex(BUF_CAP);

    let read_tls_calls = Arc::new(AtomicUsize::new(0));
    let decrypt = Arc::new(DecryptState::new());

    let mut state = state::Connected {
        server_name: ServerName::Dns("example.com".try_into().unwrap()),
        tls_client: Box::new(MockTlsClient {
            decrypt: decrypt.clone(),
            read_tls_calls: read_tls_calls.clone(),
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

    futures::executor::block_on(server_peer.write_all(&[0u8; 32])).unwrap();

    let wake_counter = WakeCounter::new();
    let waker = waker(wake_counter.clone());
    let mut cx = Context::from_waker(&waker);

    // First poll moves the server bytes into the TLS input buffer.
    {
        let mut proj = Pin::new(&mut state).project();
        Prover::<state::Connected<futures_plex::DuplexStream>>::io_to_tls_client(
            &mut proj, &mut cx,
        )
        .unwrap();
    }
    // Discard the wake for moving bytes into the buffer; the next polls are
    // the ones under test.
    wake_counter.take();

    let mut wakes = 0;
    for _ in 0..3 {
        {
            let mut proj = Pin::new(&mut state).project();
            Prover::<state::Connected<futures_plex::DuplexStream>>::io_to_tls_client(
                &mut proj, &mut cx,
            )
            .unwrap();
        }
        wakes += wake_counter.take();
    }

    assert_eq!(
        read_tls_calls.load(Ordering::Relaxed),
        0,
        "the client never wanted the buffered TLS input"
    );
    assert_eq!(
        wakes, 0,
        "buffered TLS input must not self-wake while the client is blocked"
    );
}
