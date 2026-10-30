use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
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
    wants_read: Arc<AtomicBool>,
    allow_read_tls: Arc<AtomicBool>,
    read_calls: Arc<AtomicUsize>,
    wants_write: Arc<AtomicBool>,
    unblock_write_on_poll: Arc<AtomicBool>,
    unblock_read_tls_on_poll: Arc<AtomicBool>,
    written: Arc<Mutex<Vec<u8>>>,
}

impl TlsClient for MockTlsClient {
    type Error = Error;

    fn wants_read_tls(&self) -> bool {
        self.allow_read_tls.load(Ordering::Relaxed)
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
        self.wants_read.load(Ordering::Relaxed)
    }

    fn wants_write(&self) -> bool {
        self.wants_write.load(Ordering::Relaxed)
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        // Draining the pending plaintext makes the client willing to read
        // more TLS input.
        self.wants_read.store(false, Ordering::Relaxed);
        self.allow_read_tls.store(true, Ordering::Relaxed);
        self.read_calls.fetch_add(1, Ordering::Relaxed);
        buf[0] = 0;
        Ok(1)
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
        if self.unblock_write_on_poll.load(Ordering::Relaxed) {
            self.wants_write.store(true, Ordering::Relaxed);
        }
        if self.unblock_read_tls_on_poll.load(Ordering::Relaxed) {
            self.allow_read_tls.store(true, Ordering::Relaxed);
        }
        Poll::Pending
    }
}

/// `io_from_tls_client` can drain decrypted plaintext after the client poll
/// and make `wants_read_tls` true. That transition must wake the prover once,
/// or buffered TLS input would wait for an unrelated event.
#[test]
fn readiness_change_after_io_from_wakes_once() {
    let wants_read = Arc::new(AtomicBool::new(true));
    let allow_read_tls = Arc::new(AtomicBool::new(false));
    let read_calls = Arc::new(AtomicUsize::new(0));
    let decrypt = Arc::new(DecryptState::new());

    let tls_client = MockTlsClient {
        decrypt,
        wants_read,
        allow_read_tls,
        read_calls: read_calls.clone(),
        wants_write: Arc::new(AtomicBool::new(false)),
        unblock_write_on_poll: Arc::new(AtomicBool::new(false)),
        unblock_read_tls_on_poll: Arc::new(AtomicBool::new(false)),
        written: Arc::new(Mutex::new(Vec::new())),
    };

    let mut prover = TestProver::new(Box::new(tls_client));
    prover.write_server_tls(&[0u8; 32]);

    // Prime the TLS input buffer. This call also wakes for moving the bytes.
    prover.poll_io_to().unwrap();
    prover.take_wakes();

    // The client poll cannot consume the buffered TLS yet. `io_from` drains
    // the pending plaintext, flipping wants_read_tls false -> true.
    prover.poll_io().unwrap();

    assert_eq!(read_calls.load(Ordering::Relaxed), 1);
    assert_eq!(
        prover.take_wakes(),
        1,
        "the post-io_from readiness transition must wake exactly once"
    );
}

/// A client poll that frees plaintext capacity (`wants_write` false -> true)
/// must wake the prover once, so queued application data is retried.
#[test]
fn write_readiness_change_wakes_once() {
    let written = Arc::new(Mutex::new(Vec::new()));
    let decrypt = Arc::new(DecryptState::new());

    let tls_client = MockTlsClient {
        decrypt,
        wants_read: Arc::new(AtomicBool::new(false)),
        allow_read_tls: Arc::new(AtomicBool::new(false)),
        read_calls: Arc::new(AtomicUsize::new(0)),
        wants_write: Arc::new(AtomicBool::new(false)),
        unblock_write_on_poll: Arc::new(AtomicBool::new(true)),
        unblock_read_tls_on_poll: Arc::new(AtomicBool::new(false)),
        written: written.clone(),
    };

    let mut prover = TestProver::new(Box::new(tls_client));
    prover.write_plaintext(b"hello");

    // Plaintext is queued, but the client cannot accept it yet. The client
    // poll frees capacity, flipping wants_write false -> true.
    prover.poll_io().unwrap();
    assert_eq!(
        prover.take_wakes(),
        1,
        "write readiness transition must wake exactly once"
    );
    assert!(written.lock().unwrap().is_empty());

    // The wake leads to the queued plaintext being written on the next poll.
    prover.poll_io().unwrap();
    assert_eq!(written.lock().unwrap().as_slice(), b"hello");
    assert_eq!(prover.take_wakes(), 0);
}

/// Repeated polls with no readiness transition must not wake the prover.
#[test]
fn idle_phase_does_not_wake() {
    let tls_client = MockTlsClient {
        decrypt: Arc::new(DecryptState::new()),
        wants_read: Arc::new(AtomicBool::new(false)),
        allow_read_tls: Arc::new(AtomicBool::new(false)),
        read_calls: Arc::new(AtomicUsize::new(0)),
        wants_write: Arc::new(AtomicBool::new(false)),
        unblock_write_on_poll: Arc::new(AtomicBool::new(false)),
        unblock_read_tls_on_poll: Arc::new(AtomicBool::new(false)),
        written: Arc::new(Mutex::new(Vec::new())),
    };

    let mut prover = TestProver::new(Box::new(tls_client));

    for _ in 0..3 {
        prover.poll_io().unwrap();
        assert_eq!(prover.take_wakes(), 0, "idle poll must not self-wake");
    }
}

/// When both readiness directions unblock in the same poll, wake once.
#[test]
fn both_readiness_transitions_wake_once() {
    let tls_client = MockTlsClient {
        decrypt: Arc::new(DecryptState::new()),
        wants_read: Arc::new(AtomicBool::new(false)),
        allow_read_tls: Arc::new(AtomicBool::new(false)),
        read_calls: Arc::new(AtomicUsize::new(0)),
        wants_write: Arc::new(AtomicBool::new(false)),
        unblock_write_on_poll: Arc::new(AtomicBool::new(true)),
        unblock_read_tls_on_poll: Arc::new(AtomicBool::new(true)),
        written: Arc::new(Mutex::new(Vec::new())),
    };

    let mut prover = TestProver::new(Box::new(tls_client));
    prover.write_plaintext(b"hello");
    prover.write_server_tls(&[0u8; 32]);

    // Prime the TLS input buffer; discard the byte-movement wake.
    prover.poll_io_to().unwrap();
    prover.take_wakes();

    // Both directions unblock during the client poll.
    prover.poll_io().unwrap();

    assert_eq!(
        prover.take_wakes(),
        1,
        "two readiness transitions in one poll must wake exactly once"
    );
}
