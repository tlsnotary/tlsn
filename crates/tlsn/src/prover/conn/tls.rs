use crate::prover::{Prover, state};
use futures::{AsyncRead, AsyncWrite};
use std::{
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard, Weak},
    task::{Context, Poll, Waker},
};

/// A TLS connection to a server.
///
/// This type implements [`AsyncRead`] and [`AsyncWrite`] and can be used to
/// communicate with a server using TLS.
///
/// # Note
///
/// This connection is closed on a best-effort basis if this is dropped. To
/// ensure a clean close, you should call
/// [`AsyncWriteExt::close`](futures::io::AsyncWriteExt::close) to close the
/// connection.
pub struct TlsConnection {
    prover: Weak<Mutex<Prover<state::Connected>>>,
    conn_waker: Arc<Mutex<Option<Waker>>>,
    fut_waker: Arc<Mutex<Option<Waker>>>,
    closed: bool,
}

impl TlsConnection {
    pub(crate) fn new(
        prover: Weak<Mutex<Prover<state::Connected>>>,
        conn_waker: Arc<Mutex<Option<Waker>>>,
        fut_waker: Arc<Mutex<Option<Waker>>>,
    ) -> Self {
        Self {
            prover,
            conn_waker,
            fut_waker,
            closed: false,
        }
    }

    fn conn_waker(&self) -> MutexGuard<'_, Option<Waker>> {
        self.conn_waker
            .lock()
            .expect("should be able to acquire lock for waker")
    }

    fn fut_waker(&self) -> MutexGuard<'_, Option<Waker>> {
        self.fut_waker
            .lock()
            .expect("should be able to acquire lock for waker")
    }
}

impl Drop for TlsConnection {
    fn drop(&mut self) {
        if !self.closed
            && let Some(prover) = self.prover.upgrade()
        {
            let mut prover = prover
                .lock()
                .expect("should be able to acquire lock for prover");
            prover
                .client_close()
                .expect("should be able to close connection clientside");

            if let Some(waker) = self.fut_waker().as_ref() {
                waker.wake_by_ref();
            }
            self.closed = true;
        }
    }
}

impl AsyncRead for TlsConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        if let Some(prover) = self.prover.upgrade() {
            let mut prover = prover
                .lock()
                .expect("should be able to acquire lock for prover");

            let read = prover.read(buf)?;

            if read != 0 {
                if let Some(waker) = self.fut_waker().as_ref() {
                    waker.wake_by_ref();
                }
                Poll::Ready(Ok(read))
            } else if self.closed {
                Poll::Ready(Ok(0))
            } else {
                *self.conn_waker() = Some(cx.waker().clone());
                Poll::Pending
            }
        } else {
            Poll::Ready(Ok(0))
        }
    }
}

impl AsyncWrite for TlsConnection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        if let Some(prover) = self.prover.upgrade() {
            let mut prover = prover
                .lock()
                .expect("should be able to acquire lock for prover");

            let write = prover.write(buf)?;
            if write != 0 {
                if let Some(waker) = self.fut_waker().as_ref() {
                    waker.wake_by_ref();
                }
                Poll::Ready(Ok(write))
            } else {
                *self.conn_waker() = Some(cx.waker().clone());
                Poll::Pending
            }
        } else {
            Poll::Ready(Ok(0))
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if !self.closed
            && let Some(prover) = self.prover.upgrade()
        {
            *self.conn_waker() = Some(cx.waker().clone());
            let mut prover = prover
                .lock()
                .expect("should be able to acquire lock for prover");
            prover.client_close()?;

            if let Some(waker) = self.fut_waker().as_ref() {
                waker.wake_by_ref();
            }

            self.closed = true;
            return Poll::Pending;
        }
        Poll::Ready(Ok(()))
    }
}
