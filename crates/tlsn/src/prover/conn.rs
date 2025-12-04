use crate::prover::{
    BUF_CAP, Prover, ProverError, conn::buffer::SimpleBuffer, control::ProverControl, state,
};
use futures::{AsyncRead, AsyncWrite};
use std::{
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard, Weak},
    task::{Context, Poll, Waker},
};

mod buffer;
pub(crate) mod mpc;

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

pin_project_lite::pin_project! {
    /// A future to drive the connection. Must be polled to make progress.
    pub struct ConnectionFuture<S> {
        #[pin]
        socket: S,
        prover: Option<Arc<Mutex<Prover<state::Connected>>>>,
        conn_waker: Arc<Mutex<Option<Waker>>>,
        fut_waker: Arc<Mutex<Option<Waker>>>,
        read_buf: SimpleBuffer,
        write_buf: SimpleBuffer,
    }
}

impl<S> ConnectionFuture<S> {
    pub(crate) fn new(
        socket: S,
        prover: Arc<Mutex<Prover<state::Connected>>>,
        conn_waker: Arc<Mutex<Option<Waker>>>,
        fut_waker: Arc<Mutex<Option<Waker>>>,
    ) -> Self {
        Self {
            socket,
            prover: Some(prover),
            conn_waker,
            fut_waker,
            read_buf: SimpleBuffer::default(),
            write_buf: SimpleBuffer::default(),
        }
    }

    /// Returns a handle to control the prover.
    pub fn handle(&self) -> Option<ProverControl> {
        if let Some(prover) = &self.prover {
            let ctrl = ProverControl {
                prover: Arc::downgrade(prover),
            };
            Some(ctrl)
        } else {
            None
        }
    }
}

impl<S> Future for ConnectionFuture<S>
where
    S: AsyncRead + AsyncWrite + Send,
{
    type Output = Result<Prover<state::Committed>, ProverError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        *self
            .fut_waker
            .lock()
            .expect("should be able to acquire lock for waker") = Some(cx.waker().clone());

        let mut this = self.project();
        let mut prover = this
            .prover
            .as_mut()
            .expect("prover should be available")
            .lock()
            .expect("should be able to acquire lock for prover");

        // read from socket into client
        let mut tmp_read_buf = [0_u8; BUF_CAP];

        if let Poll::Ready(read) = this.socket.as_mut().poll_read(cx, &mut tmp_read_buf)? {
            if read > 0 {
                this.read_buf.extend(&tmp_read_buf[..read]);
            } else {
                prover.server_close()?;
            }
        }

        if this.read_buf.len() > 0 {
            let read = prover.read_tls(this.read_buf.inner())?;
            this.read_buf.consume(read);
        }

        // write from client into socket
        let mut tmp_write_buf = [0_u8; BUF_CAP];
        let write = prover.write_tls(&mut tmp_write_buf)?;

        if write > 0 {
            this.write_buf.extend(&tmp_write_buf[..write]);
        }

        if this.write_buf.len() > 0
            && let Poll::Ready(write) = this
                .socket
                .as_mut()
                .poll_write(cx, this.write_buf.inner())?
        {
            this.write_buf.consume(write);
            let _ = this.socket.as_mut().poll_flush(cx)?;
        }

        // poll prover
        if let Poll::Ready(()) = prover.poll(cx)? {
            std::mem::drop(prover);

            let mut prover = this.prover.take().expect("prover should be available");
            let prover = loop {
                std::hint::spin_loop();

                match Arc::try_unwrap(prover) {
                    Ok(prover) => break prover,
                    Err(arc_prover) => prover = arc_prover,
                }
            };

            let prover = Mutex::into_inner(prover).expect("prover should be available");
            return Poll::Ready(prover.finish());
        }

        if let Some(waker) = this
            .conn_waker
            .lock()
            .expect("should be able to acquire lock for waker")
            .as_ref()
        {
            waker.wake_by_ref();
        }

        Poll::Pending
    }
}
