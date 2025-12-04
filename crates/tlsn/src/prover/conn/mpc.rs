use futures_plex::DuplexStream;
use std::{
    io::{Read, Write},
    pin::Pin,
    task::Poll,
};

use crate::prover::{Prover, ProverError, state};

pub(crate) type MpcSetupFuture =
    Box<dyn Future<Output = Result<Prover<state::CommitAccepted>, ProverError>> + Send>;

/// MPC setup for preparing a connection to the verifier.
///
/// Implements [`Read`] and [`Write`] for doing IO with the verifier.
pub struct MpcSetup {
    duplex: Option<DuplexStream>,
    setup: Pin<MpcSetupFuture>,
    prover: Option<Prover<state::CommitAccepted>>,
}

impl MpcSetup {
    pub(crate) fn new(duplex: DuplexStream, setup: MpcSetupFuture) -> Self {
        Self {
            duplex: Some(duplex),
            setup: Box::into_pin(setup),
            prover: None,
        }
    }

    /// Finishes the setup and returns a connection to the verifier and the prover.
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

impl Read for MpcSetup {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.duplex
            .as_mut()
            .expect("duplex should be available")
            .read(buf)
    }
}

impl Write for MpcSetup {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.duplex
            .as_mut()
            .expect("duplex should be available")
            .write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Future for MpcSetup {
    type Output = Result<(), ProverError>;

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let setup = Pin::new(&mut self.setup);

        if let Poll::Ready(prover) = setup.poll(cx)? {
            self.prover = Some(prover);
            return Poll::Ready(Ok(()));
        }
        Poll::Pending
    }
}

/// MPC Connection to the verifier.
///
/// Implements [`Read`] and [`Write`] for doing IO with the verifier.
pub struct MpcConnection {
    pub(crate) duplex: DuplexStream,
}

impl Read for MpcConnection {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.duplex.read(buf)
    }
}

impl Write for MpcConnection {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.duplex.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
