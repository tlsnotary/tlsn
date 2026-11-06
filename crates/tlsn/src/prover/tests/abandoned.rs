use std::{
    sync::{Arc, Mutex},
    task::Poll,
};

use mpz_common::Context as MpzContext;

use super::harness::TestProver;
use crate::{
    Error, TlsOutput,
    deps::ProverZk,
    prover::client::{DecryptState, TlsClient},
};

/// A TLS client whose decrypted plaintext is held in `pending`.
///
/// `pending` models the last stage inside the TLS client. Once the prover
/// reads from it, the bytes live in the application-side duplex instead.
struct MockTlsClient {
    decrypt: Arc<DecryptState>,
    pending: Arc<Mutex<Vec<u8>>>,
}

impl MockTlsClient {
    fn new(decrypt: Arc<DecryptState>, pending: &[u8]) -> Self {
        Self {
            decrypt,
            pending: Arc::new(Mutex::new(pending.to_vec())),
        }
    }
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
        !self.pending.lock().unwrap().is_empty()
    }

    fn wants_write(&self) -> bool {
        false
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let mut pending = self.pending.lock().unwrap();
        let n = pending.len().min(buf.len());
        buf[..n].copy_from_slice(&pending[..n]);
        pending.drain(..n);
        Ok(n)
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

fn assert_broken_pipe(err: Error) {
    assert!(err.is_io(), "expected an IO error, got: {err}");
    let source = std::error::Error::source(&err).expect("IO error should have a source");
    let io = source
        .downcast_ref::<std::io::Error>()
        .expect("source should be io::Error");
    assert_eq!(io.kind(), std::io::ErrorKind::BrokenPipe);
}

/// If the application drops its side while decrypted plaintext is still
/// pending in the TLS client, the prover must terminate instead of silently
/// ignoring the closed channel. Otherwise it can wait forever for a reader
/// that is gone.
#[test]
fn abandoned_client_with_pending_plaintext_terminates() {
    let decrypt = Arc::new(DecryptState::new());
    let tls_client = MockTlsClient::new(decrypt, b"pending");

    let mut prover = TestProver::new(Box::new(tls_client));
    prover.abandon_client();

    let err = prover
        .poll_io_from()
        .expect_err("closed client_io with pending plaintext must terminate");

    assert_broken_pipe(err);
}

/// The same abandoned channel is harmless if no plaintext is pending.
#[test]
fn abandoned_client_without_pending_plaintext_is_ignored() {
    let decrypt = Arc::new(DecryptState::new());
    let tls_client = MockTlsClient::new(decrypt, b"");

    let mut prover = TestProver::new(Box::new(tls_client));
    prover.abandon_client();

    prover
        .poll_io_from()
        .expect("closed client_io without pending plaintext should be ignored");
}

/// Plaintext that has already been copied into the application-side duplex is
/// still undelivered when the application drops before reading it. The prover
/// must fail even though the TLS client itself is now empty.
#[test]
fn abandoned_client_with_plaintext_only_in_client_io_is_fatal() {
    let decrypt = Arc::new(DecryptState::new());
    let tls_client = MockTlsClient::new(decrypt, b"hello");

    let mut prover = TestProver::new_with_client_io_cap(Box::new(tls_client), 64);

    // The prover drains the TLS client into client_io; the mock is now empty.
    prover.poll_io_from().unwrap();

    let mut one = [0u8; 1];
    assert_eq!(prover.read_app(&mut one), 1);
    assert_eq!(one[0], b'h');

    prover.abandon_client();

    let err = prover
        .poll_io_from()
        .expect_err("plaintext left in client_io must terminate the prover");

    assert_broken_pipe(err);
}

/// Plaintext still held by the TLS client is fatal even when the pipe is
/// backpressured and only part of it could be copied.
#[test]
fn abandoned_client_with_plaintext_still_in_tls_is_fatal() {
    let decrypt = Arc::new(DecryptState::new());
    let tls_client = MockTlsClient::new(decrypt, &[b'x'; 10]);

    let mut prover = TestProver::new_with_client_io_cap(Box::new(tls_client), 4);

    // Copy only four bytes; six remain in the TLS client.
    prover.poll_io_from().unwrap();

    prover.abandon_client();

    let err = prover
        .poll_io_from()
        .expect_err("plaintext still in the TLS client must terminate the prover");

    assert_broken_pipe(err);
}

/// Once the application has consumed all plaintext, an abandoned channel is
/// benign.
#[test]
fn abandoned_client_after_draining_plaintext_is_ignored() {
    let decrypt = Arc::new(DecryptState::new());
    let tls_client = MockTlsClient::new(decrypt, b"hello");

    let mut prover = TestProver::new_with_client_io_cap(Box::new(tls_client), 64);

    prover.poll_io_from().unwrap();

    let mut all = [0u8; 5];
    assert_eq!(prover.read_app(&mut all), 5);

    prover.abandon_client();

    prover
        .poll_io_from()
        .expect("a drained client_io must be ignored");
}
