use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{AsyncWrite, AsyncWriteExt, task::waker};

use super::harness::WakeCounter;

struct FailingWriter {
    kind: io::ErrorKind,
}

impl AsyncWrite for FailingWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(self.kind.into()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn receiver_with_data() -> futures_plex::DuplexStream {
    let (mut sender, receiver) = futures_plex::duplex(64);
    futures::executor::block_on(sender.write_all(b"tls record")).unwrap();
    receiver
}

#[test]
fn ignores_server_broken_pipe_without_waking() {
    let receiver = receiver_with_data();
    let wake_counter = WakeCounter::new();
    let waker = waker(wake_counter.clone());
    let mut cx = Context::from_waker(&waker);

    crate::prover::poll_write_to_server(
        &mut cx,
        &receiver,
        FailingWriter {
            kind: io::ErrorKind::BrokenPipe,
        },
    )
    .expect("BrokenPipe is intentionally ignored");

    // The bytes stay queued and no waker is armed; if the server read side
    // never closes, this drain has nothing to wake it.
    assert_eq!(wake_counter.take(), 0);
}

#[test]
fn ignores_server_connection_reset_without_waking() {
    let receiver = receiver_with_data();
    let wake_counter = WakeCounter::new();
    let waker = waker(wake_counter.clone());
    let mut cx = Context::from_waker(&waker);

    crate::prover::poll_write_to_server(
        &mut cx,
        &receiver,
        FailingWriter {
            kind: io::ErrorKind::ConnectionReset,
        },
    )
    .expect("ConnectionReset is intentionally ignored");

    assert_eq!(wake_counter.take(), 0);
}

#[test]
fn propagates_other_server_write_errors() {
    let receiver = receiver_with_data();
    let wake_counter = WakeCounter::new();
    let waker = waker(wake_counter.clone());
    let mut cx = Context::from_waker(&waker);

    let err = crate::prover::poll_write_to_server(
        &mut cx,
        &receiver,
        FailingWriter {
            kind: io::ErrorKind::Other,
        },
    )
    .expect_err("other write errors must propagate");

    assert!(err.is_io(), "expected an IO error, got: {err}");
}
