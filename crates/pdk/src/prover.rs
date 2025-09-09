use std::{
    future::poll_fn,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{AsyncRead, AsyncWrite};
use tlsn_core::transcript::{TlsTranscript, Transcript};

use crate::abi;

pub use tlsn_core::{
    ProverOutput,
    config::{ProveConfig, ProverConfig},
};

#[derive(Debug)]
pub struct ProverError {}

impl std::error::Error for ProverError {}

impl std::fmt::Display for ProverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ProverError")
    }
}

pub mod state {
    use tlsn_core::transcript::{TlsTranscript, Transcript};

    mod sealed {
        pub trait Sealed {}
    }

    pub trait ProverState: sealed::Sealed {}

    pub struct Initialized {}
    pub struct Setup {}
    pub struct Committed {
        pub(super) tls_transcript: TlsTranscript,
        pub(super) transcript: Transcript,
    }

    impl sealed::Sealed for Initialized {}
    impl sealed::Sealed for Setup {}
    impl sealed::Sealed for Committed {}

    impl ProverState for Initialized {}
    impl ProverState for Setup {}
    impl ProverState for Committed {}
}

pub struct Prover<T: state::ProverState = state::Initialized> {
    handle: abi::prove::Prover,
    state: T,
}

impl Prover {
    /// Creates a new prover.
    ///
    /// # Arguments
    ///
    /// * `config` - The configuration for the prover.
    pub fn new(config: ProverConfig) -> Self {
        let config = bincode::serialize(&config).unwrap();

        let handle = abi::prove::Prover::new(&config);

        Self {
            handle,
            state: state::Initialized {},
        }
    }

    pub async fn setup(self) -> Result<Prover<state::Setup>, ProverError> {
        poll_fn(|_| {
            if let abi::prove::SetupReturn::Ready = self.handle.setup() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;

        Ok(Prover {
            handle: self.handle,
            state: state::Setup {},
        })
    }
}

impl Prover<state::Setup> {
    pub async fn connect(self) -> Result<(TlsConnection, ProverFuture), ProverError> {
        let io = poll_fn(|_| {
            if let abi::prove::ConnectReturn::Ready(io) = self.handle.connect() {
                Poll::Ready(io)
            } else {
                Poll::Pending
            }
        })
        .await;

        Ok((
            TlsConnection { handle: io },
            ProverFuture {
                handle: Some(self.handle),
            },
        ))
    }
}

impl Prover<state::Committed> {
    pub fn tls_transcript(&self) -> &TlsTranscript {
        &self.state.tls_transcript
    }

    pub fn transcript(&self) -> &Transcript {
        &self.state.transcript
    }

    pub async fn prove(&mut self, config: &ProveConfig) -> Result<ProverOutput, ProverError> {
        let config = bincode::serialize(&config).unwrap();

        self.handle.prove(&config);

        let res = poll_fn(|_| {
            if let abi::prove::ProveReturn::Ready(res) = self.handle.finish_prove() {
                Poll::Ready(res)
            } else {
                Poll::Pending
            }
        })
        .await;

        res.map(|output| bincode::deserialize(&output).unwrap())
            .map_err(|_| todo!())
    }

    pub async fn close(self) -> Result<(), ProverError> {
        poll_fn(|_| {
            if let abi::prove::CloseReturn::Ready = self.handle.close() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;

        Ok(())
    }
}

pub struct ProverFuture {
    handle: Option<abi::prove::Prover>,
}

impl Future for ProverFuture {
    type Output = Result<Prover<state::Committed>, ProverError>;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let handle = self
            .handle
            .take()
            .expect("future should not be polled after completion.");

        if let abi::prove::CommitReturn::Ready(res) = handle.finish_commit() {
            Poll::Ready(
                res.map(|data| {
                    let (tls_transcript, transcript) = bincode::deserialize(&data).unwrap();

                    Prover {
                        handle: handle,
                        state: state::Committed {
                            tls_transcript,
                            transcript,
                        },
                    }
                })
                .map_err(|_| todo!()),
            )
        } else {
            self.handle = Some(handle);
            Poll::Pending
        }
    }
}

pub struct TlsConnection {
    handle: abi::io::Io,
}

impl AsyncWrite for TlsConnection {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let n = match self.handle.check_write() {
            abi::io::CheckWriteReturn::Pending => {
                return Poll::Pending;
            }
            abi::io::CheckWriteReturn::Ready(Ok(n)) => (n as usize).min(buf.len()),
            abi::io::CheckWriteReturn::Ready(Err(e)) => {
                return Poll::Ready(Err(match e {
                    abi::io::Error::Closed => {
                        io::Error::new(io::ErrorKind::ConnectionAborted, "connection closed")
                    }
                    abi::io::Error::Other(e) => io::Error::new(io::ErrorKind::Other, e),
                }));
            }
        };

        self.handle.write(&buf[..n]).unwrap();

        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.handle.close() {
            abi::io::CloseReturn::Pending => Poll::Pending,
            abi::io::CloseReturn::Ready(Ok(())) => Poll::Ready(Ok(())),
            abi::io::CloseReturn::Ready(Err(e)) => Poll::Ready(Err(match e {
                abi::io::Error::Closed => {
                    io::Error::new(io::ErrorKind::ConnectionAborted, "connection closed")
                }
                abi::io::Error::Other(e) => io::Error::new(io::ErrorKind::Other, e),
            })),
        }
    }
}

impl AsyncRead for TlsConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        match self.handle.read(buf.len() as u32) {
            abi::io::ReadReturn::Pending => Poll::Pending,
            abi::io::ReadReturn::Ready(Ok(data)) => {
                assert!(data.len() <= buf.len());
                buf[..data.len()].copy_from_slice(&data);

                Poll::Ready(Ok(data.len()))
            }
            abi::io::ReadReturn::Ready(Err(abi::io::Error::Closed)) => Poll::Ready(Ok(0)),
            abi::io::ReadReturn::Ready(Err(e)) => {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e)))
            }
        }
    }
}
