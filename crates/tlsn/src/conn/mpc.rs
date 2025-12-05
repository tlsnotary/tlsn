use crate::{
    BUF_CAP,
    conn::buffer::SimpleBuffer,
    prover::{Prover, ProverError, state},
};
use futures::{AsyncRead, AsyncWrite};
use futures_plex::DuplexStream;
use std::{
    io::{Read, Write},
    pin::Pin,
    task::Poll,
};

pub(crate) type MpcSetupFuture =
    Box<dyn Future<Output = Result<Prover<state::CommitAccepted>, ProverError>> + Send>;

/// MPC setup for preparing a connection to the verifier.
///
/// Implements [`Read`] and [`Write`] for doing IO with the verifier.
pub struct MpcSetup {
    pub(crate) duplex: Option<DuplexStream>,
    pub(crate) setup: Pin<MpcSetupFuture>,
}

impl MpcSetup {
    pub(crate) fn new(duplex: DuplexStream, setup: MpcSetupFuture) -> Self {
        Self {
            duplex: Some(duplex),
            setup: Box::into_pin(setup),
        }
    }

    /// Writes bytes for the verifier into a buffer.
    ///
    /// # Arguments
    ///
    /// * `buf` - The buffer.
    pub fn write_mpc(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let duplex = self.duplex.as_mut().unwrap();
        Read::read(duplex, buf)
    }

    /// Reads bytes for the prover from a buffer.
    ///
    /// # Arguments
    ///
    /// * `buf` - The buffer.
    pub fn read_mpc(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let duplex = self.duplex.as_mut().unwrap();
        Write::write(duplex, buf)
    }

    /// Drives the setup process. Must be polled to make progress. Returns
    ///
    /// # Arguments
    ///
    /// * `cx` - The context.
    ///
    /// # Returns
    ///
    /// * [`MpcConnection`] for communicating with the verifier.
    /// * [`Prover`] to connect with the server.
    pub fn poll(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(MpcConnection, Prover<state::CommitAccepted>), ProverError>> {
        if let Poll::Ready(prover) = self.setup.as_mut().poll(cx)? {
            let mpc_conn = MpcConnection {
                duplex: self.duplex.take().expect("duplex should be available"),
            };
            let output = (mpc_conn, prover);
            return Poll::Ready(Ok(output));
        }
        Poll::Pending
    }
}

/// MPC Connection to the verifier.
///
/// Implements [`Read`] and [`Write`] for doing IO with the verifier.
pub struct MpcConnection {
    duplex: DuplexStream,
}

impl MpcConnection {
    pub(crate) fn new(duplex: DuplexStream) -> Self {
        Self { duplex }
    }

    /// Writes bytes for the verifier into a buffer.
    ///
    /// # Arguments
    ///
    /// * `buf` - The buffer.
    pub fn write_mpc(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        Read::read(&mut self.duplex, buf)
    }

    /// Reads bytes for the prover from a buffer.
    ///
    /// # Arguments
    ///
    /// * `buf` - The buffer.
    pub fn read_mpc(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Write::write(&mut self.duplex, buf)
    }

    /// Attaches a socket to the connection and returns a future that must be
    /// polled to make progress.
    ///
    /// # Arguments
    ///
    /// * `socket` - The socket for the prover <-> verifier connection.
    pub fn into_future<S>(self, socket: S) -> MpcFuture<S>
    where
        S: AsyncRead + AsyncWrite + Send,
    {
        MpcFuture {
            duplex: self.duplex,
            socket,
            read_buf: SimpleBuffer::default(),
            write_buf: SimpleBuffer::default(),
        }
    }
}

pin_project_lite::pin_project! {
    pub struct MpcFuture<S> {
        #[pin]
        duplex: DuplexStream,
        #[pin]
        socket: S,
        read_buf: SimpleBuffer,
        write_buf: SimpleBuffer,
    }
}

impl<S> Future for MpcFuture<S>
where
    S: AsyncRead + AsyncWrite + Send,
{
    type Output = Result<(), std::io::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();

        loop {
            let mut is_pending = true;

            // read from socket into client
            let mut tmp_read_buf = [0_u8; BUF_CAP];

            if let Poll::Ready(read) = this.socket.as_mut().poll_read(cx, &mut tmp_read_buf)? {
                is_pending = false;
                if read > 0 {
                    this.read_buf.extend(&tmp_read_buf[..read]);
                } else {
                    return this.duplex.as_mut().poll_close(cx);
                }
            }

            if this.read_buf.len() > 0
                && let Poll::Ready(write) =
                    this.duplex.as_mut().poll_write(cx, this.read_buf.inner())?
            {
                is_pending = false;
                this.read_buf.consume(write);
            }

            // read from client into socket
            let mut tmp_write_buf = [0_u8; BUF_CAP];

            if let Poll::Ready(read) = this.duplex.as_mut().poll_read(cx, &mut tmp_write_buf)? {
                is_pending = false;
                if read > 0 {
                    this.write_buf.extend(&tmp_write_buf[..read]);
                } else {
                    return this.duplex.as_mut().poll_close(cx);
                }
            }

            if this.write_buf.len() > 0
                && let Poll::Ready(write) = this
                    .socket
                    .as_mut()
                    .poll_write(cx, this.write_buf.inner())?
            {
                is_pending = false;
                this.write_buf.consume(write);
            }

            if is_pending {
                return Poll::Pending;
            }
        }
    }
}
