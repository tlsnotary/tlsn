use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
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

struct MockProxyTlsClient {
    decrypt: Arc<DecryptState>,
    wants_read_tls: Arc<AtomicBool>,
    unblock_read_on_poll: Arc<AtomicBool>,
}

impl TlsClient for MockProxyTlsClient {
    type Error = Error;

    fn wants_read_tls(&self) -> bool {
        self.wants_read_tls.load(Ordering::Relaxed)
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

    // Proxy clients report write readiness from connection state, not buffer
    // capacity, so this stays true while connected.
    fn wants_write(&self) -> bool {
        true
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
        if self.unblock_read_on_poll.load(Ordering::Relaxed) {
            self.wants_read_tls.store(true, Ordering::Relaxed);
        }
        Poll::Pending
    }
}

fn client(unblock_read_on_poll: bool) -> MockProxyTlsClient {
    MockProxyTlsClient {
        decrypt: Arc::new(DecryptState::new()),
        wants_read_tls: Arc::new(AtomicBool::new(false)),
        unblock_read_on_poll: Arc::new(AtomicBool::new(unblock_read_on_poll)),
    }
}

/// Constant-true `wants_write` (proxy semantics) must not produce a
/// false progress wake.
#[test]
fn proxy_constant_write_readiness_does_not_wake() {
    let mut prover = TestProver::new(Box::new(client(false)));

    for _ in 0..3 {
        prover.poll_io().unwrap();
        assert_eq!(
            prover.take_wakes(),
            0,
            "constant write readiness must not self-wake"
        );
    }
}

/// A proxy read-readiness transition must still wake once, even though
/// `wants_write` is constantly true.
#[test]
fn proxy_read_readiness_transition_wakes_once() {
    let mut prover = TestProver::new(Box::new(client(true)));
    prover.write_server_tls(&[0u8; 32]);

    // Prime the TLS input buffer; discard the byte-movement wake.
    prover.poll_io_to().unwrap();
    prover.take_wakes();

    // The client poll makes itself willing to read TLS input.
    prover.poll_io().unwrap();

    assert_eq!(
        prover.take_wakes(),
        1,
        "proxy read readiness transition must wake exactly once"
    );
}
