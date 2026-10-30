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
    remaining: Arc<AtomicUsize>,
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
        self.remaining.load(Ordering::Relaxed) > 0
    }

    fn wants_write(&self) -> bool {
        false
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let remaining = self.remaining.load(Ordering::Relaxed);
        let n = remaining.min(buf.len());
        buf[..n].fill(0);
        self.remaining.fetch_sub(n, Ordering::Relaxed);
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

/// A live but slow application must not stall the close drain. Once
/// `client_io` fills, the write waker is armed; an application read wakes the
/// prover so it can drain the remaining plaintext.
#[test]
fn slow_app_read_wakes_close_drain() {
    const CAP: usize = 8;

    let remaining = Arc::new(AtomicUsize::new(32));
    let tls_client = MockTlsClient {
        decrypt: Arc::new(DecryptState::new()),
        remaining: remaining.clone(),
    };

    let mut prover = TestProver::new_with_client_io_cap(Box::new(tls_client), CAP);

    // Fill the application buffer.
    prover.poll_io_from().unwrap();
    // The buffer is full now: this poll arms the write waker but must not
    // self-wake.
    prover.poll_io_from().unwrap();
    assert_eq!(prover.take_wakes(), 0, "full client_io must not self-wake");

    // The application reads, freeing space and waking the prover.
    let mut buf = [0u8; 4];
    assert_eq!(prover.read_app(&mut buf), 4);
    assert_eq!(
        prover.take_wakes(),
        1,
        "application read must wake the prover"
    );

    // The drain continues after the wake.
    let before = remaining.load(Ordering::Relaxed);
    prover.poll_io_from().unwrap();
    assert!(
        remaining.load(Ordering::Relaxed) < before,
        "plaintext should drain after the application makes room"
    );
}
