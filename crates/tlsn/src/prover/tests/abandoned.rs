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

struct MockTlsClient {
    decrypt: Arc<DecryptState>,
    wants_read: Arc<AtomicBool>,
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
        self.wants_read.load(Ordering::Relaxed)
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
    let decrypt = Arc::new(DecryptState::new());
    let tls_client = MockTlsClient {
        decrypt,
        wants_read: Arc::new(AtomicBool::new(true)),
    };

    let mut prover = TestProver::new(Box::new(tls_client));
    prover.abandon_client();

    let err = prover
        .poll_io_from()
        .expect_err("closed client_io with pending plaintext must terminate");

    assert!(err.is_io(), "expected an IO error, got: {err}");
    let source = std::error::Error::source(&err).expect("IO error should have a source");
    let io = source
        .downcast_ref::<std::io::Error>()
        .expect("source should be io::Error");
    assert_eq!(io.kind(), std::io::ErrorKind::BrokenPipe);
}

/// The same abandoned channel is harmless if no plaintext is pending.
#[test]
fn abandoned_client_without_pending_plaintext_is_ignored() {
    let decrypt = Arc::new(DecryptState::new());
    let tls_client = MockTlsClient {
        decrypt,
        wants_read: Arc::new(AtomicBool::new(false)),
    };

    let mut prover = TestProver::new(Box::new(tls_client));
    prover.abandon_client();

    prover
        .poll_io_from()
        .expect("closed client_io without pending plaintext should be ignored");
}
