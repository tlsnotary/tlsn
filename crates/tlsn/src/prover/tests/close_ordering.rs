//! Close ordering between the staging channel and the server socket.
//!
//! The prover produces TLS bytes into a staging channel and forwards them to
//! the server socket from there, so the socket may only be closed once the
//! channel is both closed and drained. Otherwise records the client already
//! produced are dropped and the peer sees a truncated stream.

use std::{
    sync::{Arc, Mutex},
    task::Poll,
};

use futures::task::noop_waker_ref;
use mpz_common::Context as MpzContext;

use super::harness::TestProver;
use crate::{
    Error, TlsOutput,
    deps::ProverZk,
    prover::client::{DecryptState, TlsClient},
};

/// A client that emits a fixed buffer of TLS bytes and then asks for the
/// transport write half to be closed.
struct ClosingClient {
    decrypt: Arc<DecryptState>,
    pending: Vec<u8>,
    /// Bytes handed out so far, for assertions.
    emitted: Arc<Mutex<Vec<u8>>>,
    /// Whether the client asks for the transport to be shut down once its
    /// output has been drained.
    wants_shutdown: bool,
    shutdown_done: bool,
}

impl ClosingClient {
    fn new(payload: &[u8], wants_shutdown: bool) -> (Self, Arc<Mutex<Vec<u8>>>) {
        let emitted = Arc::new(Mutex::new(Vec::new()));
        let client = Self {
            decrypt: Arc::new(DecryptState::new()),
            pending: payload.to_vec(),
            emitted: emitted.clone(),
            wants_shutdown,
            shutdown_done: false,
        };
        (client, emitted)
    }
}

impl TlsClient for ClosingClient {
    type Error = Error;

    fn wants_read_tls(&self) -> bool {
        false
    }

    fn wants_write_tls(&self) -> bool {
        !self.pending.is_empty()
    }

    fn read_tls(&mut self, _buf: &[u8]) -> Result<usize, Self::Error> {
        Ok(0)
    }

    fn write_tls(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let n = buf.len().min(self.pending.len());
        buf[..n].copy_from_slice(&self.pending[..n]);
        self.pending.drain(..n);
        self.emitted.lock().unwrap().extend_from_slice(&buf[..n]);
        Ok(n)
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

    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        Ok(buf.len())
    }

    fn client_close(&mut self) {}

    fn server_close(&mut self) {}

    /// Only ask for shutdown once everything has been handed over, the same
    /// way the proxy client does.
    fn wants_write_shutdown(&self) -> bool {
        self.wants_shutdown && self.pending.is_empty() && !self.shutdown_done
    }

    fn write_shutdown_complete(&mut self) {
        self.shutdown_done = true;
    }

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

/// Reads everything the prover has forwarded so far, without blocking.
fn drain_server(prover: &mut TestProver) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cx = std::task::Context::from_waker(noop_waker_ref());
    loop {
        let mut buf = [0u8; 4096];
        match prover.poll_read_server(&mut cx, &mut buf) {
            Poll::Ready(Ok(0)) => break,
            Poll::Ready(Ok(n)) => out.extend_from_slice(&buf[..n]),
            Poll::Ready(Err(err)) => panic!("server read failed: {err}"),
            // Nothing available yet.
            Poll::Pending => break,
        }
    }
    out
}

/// Whether the prover has finished with and closed the server socket.
fn server_finished(prover: &mut TestProver) -> bool {
    let mut cx = std::task::Context::from_waker(noop_waker_ref());
    let mut buf = [0u8; 1];
    matches!(prover.poll_read_server(&mut cx, &mut buf), Poll::Ready(Ok(0)))
}

/// The transport is not closed while TLS bytes are still staged: every byte
/// reaches the server first, and only then does the stream end.
#[test]
fn close_waits_for_all_staged_bytes() {
    let payload = [7u8; 32];
    let (client, _emitted) = ClosingClient::new(&payload, true);
    let mut prover = TestProver::new_with_caps(Box::new(client), 1024, 1024, 4);

    let mut received = Vec::new();

    // Bounded so a hang fails fast instead of spinning.
    for _ in 0..64 {
        prover.poll_io().unwrap();
        received.extend(drain_server(&mut prover));
        if server_finished(&mut prover) {
            break;
        }
    }

    assert_eq!(
        received, payload,
        "the server must receive every staged byte before the transport ends"
    );
    assert!(prover.pipe_closed(), "the staging channel is closed");
    assert!(prover.pipe_drained(), "the staging channel is drained");
}

/// The socket is not closed while the client still has output to hand over.
#[test]
fn close_does_not_happen_while_output_is_pending() {
    let payload = [3u8; 64];
    let (client, _emitted) = ClosingClient::new(&payload, true);
    // A tiny socket buffer keeps the bytes in the channel across polls.
    let mut prover = TestProver::new_with_caps(Box::new(client), 1024, 1024, 8);

    prover.poll_io().unwrap();

    assert!(
        !prover.pipe_closed(),
        "the staging channel must stay open while bytes remain staged"
    );
    assert!(
        !server_finished(&mut prover),
        "the transport must not be closed while bytes are still staged"
    );

    let first = drain_server(&mut prover);
    assert!(
        !first.is_empty() && first.len() < payload.len(),
        "only part of the payload should have been forwarded, got {}",
        first.len()
    );
}

/// Without a shutdown request the channel is never closed, so forwarding keeps
/// working indefinitely.
#[test]
fn no_shutdown_request_leaves_the_channel_open() {
    let payload = [1u8; 16];
    let (client, _emitted) = ClosingClient::new(&payload, false);
    let mut prover = TestProver::new_with_caps(Box::new(client), 1024, 1024, 1024);

    for _ in 0..4 {
        prover.poll_io().unwrap();
    }

    assert_eq!(drain_server(&mut prover), payload);
    assert!(!prover.pipe_closed(), "nothing requested a shutdown");
    assert!(!server_finished(&mut prover), "the transport stays open");
}

/// Polls once and drains whatever reached the server, returning the number of
/// wake-ups that poll produced.
fn poll_and_drain(prover: &mut TestProver) -> (usize, Vec<u8>) {
    prover.poll_io().unwrap();
    let wakes = prover.take_wakes();
    (wakes, drain_server(prover))
}

/// Wake accounting across the whole emit, drain and close sequence.
#[test]
fn wake_counts_are_exact_across_emit_drain_and_close() {
    let payload = [9u8; 8];
    let (client, _emitted) = ClosingClient::new(&payload, true);
    // Four bytes at a time, so emission and forwarding need several polls.
    let mut prover = TestProver::new_with_caps(Box::new(client), 1024, 1024, 4);

    // Emits all eight bytes and forwards four: one wake for the forwarding
    // progress, one for the emission progress.
    let (wakes, received) = poll_and_drain(&mut prover);
    assert_eq!(wakes, 2, "a poll that emits and forwards wakes twice");
    assert_eq!(received.len(), 4);

    // Closes the channel and forwards the remaining four: only forwarding
    // progresses.
    let (wakes, received) = poll_and_drain(&mut prover);
    assert_eq!(wakes, 1, "a poll that only forwards wakes once");
    assert_eq!(received.len(), 4);

    // Observes the channel empty and closed, then closes the transport, which
    // wakes once so the loop can observe completion.
    let (wakes, received) = poll_and_drain(&mut prover);
    assert_eq!(wakes, 1, "closing the transport wakes once");
    assert!(received.is_empty());
    assert!(prover.pipe_drained());

    // Nothing left to do.
    let (wakes, received) = poll_and_drain(&mut prover);
    assert_eq!(wakes, 0, "a drained prover must not wake");
    assert!(received.is_empty());
}

/// Regression: once drained, further polls must not write into the socket that
/// is being closed, which would surface as a write to a closed stream.
#[test]
fn no_writes_after_the_socket_is_closed() {
    let payload = [5u8; 4];
    let (client, _emitted) = ClosingClient::new(&payload, true);
    let mut prover = TestProver::new_with_caps(Box::new(client), 1024, 1024, 1024);

    let mut received = Vec::new();
    for _ in 0..16 {
        received.extend(poll_and_drain(&mut prover).1);
        if server_finished(&mut prover) {
            break;
        }
    }
    assert!(prover.pipe_drained());
    assert_eq!(received, payload);

    // Nothing is left, so these must be no-ops rather than errors or wakes.
    for _ in 0..4 {
        let (wakes, received) = poll_and_drain(&mut prover);
        assert_eq!(wakes, 0, "a drained prover must not keep waking");
        assert!(received.is_empty());
    }
}
