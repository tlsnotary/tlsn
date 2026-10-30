use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::Poll,
};

use mpz_common::Context as MpzContext;

use super::harness::TestProver;
use crate::{
    Error, TlsOutput,
    deps::ProverZk,
    prover::client::{DecryptState, TlsClient},
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
    let read_tls_calls = Arc::new(AtomicUsize::new(0));
    let decrypt = Arc::new(DecryptState::new());

    let tls_client = MockTlsClient {
        decrypt,
        read_tls_calls: read_tls_calls.clone(),
    };

    let mut prover = TestProver::new(Box::new(tls_client));
    prover.write_server_tls(&[0u8; 32]);

    // First poll moves the server bytes into the TLS input buffer.
    prover.poll_io_to().unwrap();
    // Discard the wake for moving bytes into the buffer; the next polls are
    // the ones under test.
    prover.take_wakes();

    let mut wakes = 0;
    for _ in 0..3 {
        prover.poll_io_to().unwrap();
        wakes += prover.take_wakes();
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
