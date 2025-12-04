use crate::prover::{Prover, ProverError, state};
use futures::{AsyncRead, AsyncReadExt, AsyncWrite};
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
    pub(crate) prover: Option<Prover<state::CommitAccepted>>,
}

impl MpcSetup {
    pub(crate) fn new(duplex: DuplexStream, setup: MpcSetupFuture) -> Self {
        Self {
            duplex: Some(duplex),
            setup: Box::into_pin(setup),
            prover: None,
        }
    }

    /// Writes bytes for the verifier into a buffer.
    ///
    /// # Arguments
    ///
    /// * `buf` - The buffer.
    pub fn write_mpc(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let duplex = self.duplex.as_mut().expect("duplex should be available");
        Read::read(duplex, buf)
    }

    /// Reads bytes for the prover from a buffer.
    ///
    /// # Arguments
    ///
    /// * `buf` - The buffer.
    pub fn read_mpc(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let duplex = self.duplex.as_mut().expect("duplex should be available");
        Write::write(duplex, buf)
    }

    /// Drives the setup process. Must be polled to make progress.
    ///
    /// # Arguments
    ///
    /// * `cx` - The context.
    pub fn poll(&mut self, cx: &mut std::task::Context<'_>) -> Poll<Result<(), ProverError>> {
        if let Poll::Ready(prover) = self.setup.as_mut().poll(cx)? {
            self.prover = Some(prover);
            return Poll::Ready(Ok(()));
        }
        Poll::Pending
    }

    /// Finishes the setup and returns
    ///     - [`MpcConnection`] for communicating with the verifier.
    ///     - [`Prover`] to connect with the server.
    pub fn finish(&mut self) -> Option<(MpcConnection, Prover<state::CommitAccepted>)> {
        match self.prover.take() {
            Some(prover) => Some((
                MpcConnection {
                    duplex: self.duplex.take().expect("duplex should be available"),
                },
                prover,
            )),
            None => None,
        }
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
        self.duplex.write(buf)
    }

    /// Attaches a socket to the connection and returns a future that must be polled to make
    /// progress.
    ///
    /// # Arguments
    ///
    /// * `socket` - The socket for the prover <-> verifier connection.
    pub fn into_future<'a, S>(self, socket: S) -> MpcFuture<'a>
    where
        S: AsyncRead + AsyncWrite + Send + 'a,
    {
        let fut = async move {
            let (duplex_read, mut duplex_write) = self.duplex.split();
            let (socket_read, mut socket_write) = socket.split();

            let read = futures::io::copy(socket_read, &mut duplex_write);
            let write = futures::io::copy(duplex_read, &mut socket_write);

            futures::future::try_join(read, write).await
        };

        MpcFuture { fut: Box::pin(fut) }
    }
}

pub(crate) type CopyFuture<'a> = Pin<Box<dyn Future<Output = std::io::Result<(u64, u64)>> + 'a>>;

pub struct MpcFuture<'a> {
    fut: CopyFuture<'a>,
}

impl<'a> Future for MpcFuture<'a> {
    type Output = Result<(u64, u64), std::io::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        self.fut.as_mut().poll(cx)
    }
}
