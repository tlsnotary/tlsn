use std::{error::Error, fmt};
use tls_mpc::MpcTlsError;

/// Error for [`Prover`](crate::Prover).
#[derive(Debug, thiserror::Error)]
pub struct ProverError {
    kind: ErrorKind,
    source: Option<Box<dyn Error + Send + Sync + 'static>>,
}

impl ProverError {
    fn new<E>(kind: ErrorKind, source: E) -> Self
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self {
            kind,
            source: Some(source.into()),
        }
    }

    pub(crate) fn config<E>(source: E) -> Self
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self::new(ErrorKind::Config, source)
    }

    pub(crate) fn attestation<E>(source: E) -> Self
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self::new(ErrorKind::Attestation, source)
    }
}

#[derive(Debug)]
enum ErrorKind {
    Io,
    Mpc,
    Config,
    Attestation,
}

impl fmt::Display for ProverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("prover error: ")?;

        match self.kind {
            ErrorKind::Io => f.write_str("io error")?,
            ErrorKind::Mpc => f.write_str("mpc error")?,
            ErrorKind::Config => f.write_str("config error")?,
            ErrorKind::Attestation => f.write_str("attestation error")?,
        }

        if let Some(source) = &self.source {
            write!(f, " caused by: {}", source)?;
        }

        Ok(())
    }
}

impl From<std::io::Error> for ProverError {
    fn from(e: std::io::Error) -> Self {
        Self::new(ErrorKind::Io, e)
    }
}

impl From<tls_client_async::ConnectionError> for ProverError {
    fn from(e: tls_client_async::ConnectionError) -> Self {
        Self::new(ErrorKind::Io, e)
    }
}

impl From<uid_mux::yamux::ConnectionError> for ProverError {
    fn from(e: uid_mux::yamux::ConnectionError) -> Self {
        Self::new(ErrorKind::Io, e)
    }
}

impl From<mpz_common::ContextError> for ProverError {
    fn from(e: mpz_common::ContextError) -> Self {
        Self::new(ErrorKind::Mpc, e)
    }
}

impl From<MpcTlsError> for ProverError {
    fn from(e: MpcTlsError) -> Self {
        Self::new(ErrorKind::Mpc, e)
    }
}

impl From<mpz_ot::OTError> for ProverError {
    fn from(e: mpz_ot::OTError) -> Self {
        Self::new(ErrorKind::Mpc, e)
    }
}

impl From<mpz_ot::kos::SenderError> for ProverError {
    fn from(e: mpz_ot::kos::SenderError) -> Self {
        Self::new(ErrorKind::Mpc, e)
    }
}

impl From<mpz_ole::OLEError> for ProverError {
    fn from(e: mpz_ole::OLEError) -> Self {
        Self::new(ErrorKind::Mpc, e)
    }
}

impl From<mpz_ot::kos::ReceiverError> for ProverError {
    fn from(e: mpz_ot::kos::ReceiverError) -> Self {
        Self::new(ErrorKind::Mpc, e)
    }
}

impl From<mpz_garble::VmError> for ProverError {
    fn from(e: mpz_garble::VmError) -> Self {
        Self::new(ErrorKind::Mpc, e)
    }
}

impl From<mpz_garble::protocol::deap::DEAPError> for ProverError {
    fn from(e: mpz_garble::protocol::deap::DEAPError) -> Self {
        Self::new(ErrorKind::Mpc, e)
    }
}

impl From<mpz_garble::MemoryError> for ProverError {
    fn from(e: mpz_garble::MemoryError) -> Self {
        Self::new(ErrorKind::Mpc, e)
    }
}

impl From<mpz_garble::ProveError> for ProverError {
    fn from(e: mpz_garble::ProveError) -> Self {
        Self::new(ErrorKind::Mpc, e)
    }
}
