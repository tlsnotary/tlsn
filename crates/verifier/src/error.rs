use std::{error::Error, fmt};
use tls_mpc::MpcTlsError;

/// Error for [`Verifier`](crate::Verifier).
#[derive(Debug, thiserror::Error)]
pub struct VerifierError {
    kind: ErrorKind,
    source: Option<Box<dyn Error + Send + Sync + 'static>>,
}

impl VerifierError {
    fn new<E>(kind: ErrorKind, source: E) -> Self
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self {
            kind,
            source: Some(source.into()),
        }
    }

    pub(crate) fn attestation<E>(source: E) -> Self
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self::new(ErrorKind::Attestation, source)
    }

    pub(crate) fn verify<E>(source: E) -> Self
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self::new(ErrorKind::Verify, source)
    }
}

#[derive(Debug)]
enum ErrorKind {
    Io,
    Config,
    Mpc,
    Attestation,
    Verify,
}

impl fmt::Display for VerifierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("verifier error: ")?;

        match self.kind {
            ErrorKind::Io => f.write_str("io error")?,
            ErrorKind::Config => f.write_str("config error")?,
            ErrorKind::Mpc => f.write_str("mpc error")?,
            ErrorKind::Attestation => f.write_str("attestation error")?,
            ErrorKind::Verify => f.write_str("verification error")?,
        }

        if let Some(source) = &self.source {
            write!(f, " caused by: {}", source)?;
        }

        Ok(())
    }
}

impl From<std::io::Error> for VerifierError {
    fn from(e: std::io::Error) -> Self {
        Self::new(ErrorKind::Io, e)
    }
}

impl From<tlsn_common::config::ProtocolConfigError> for VerifierError {
    fn from(e: tlsn_common::config::ProtocolConfigError) -> Self {
        Self::new(ErrorKind::Config, e)
    }
}

impl From<uid_mux::yamux::ConnectionError> for VerifierError {
    fn from(e: uid_mux::yamux::ConnectionError) -> Self {
        Self::new(ErrorKind::Io, e)
    }
}

impl From<mpz_common::ContextError> for VerifierError {
    fn from(e: mpz_common::ContextError) -> Self {
        Self::new(ErrorKind::Mpc, e)
    }
}

impl From<MpcTlsError> for VerifierError {
    fn from(e: MpcTlsError) -> Self {
        Self::new(ErrorKind::Mpc, e)
    }
}

impl From<mpz_ot::OTError> for VerifierError {
    fn from(e: mpz_ot::OTError) -> Self {
        Self::new(ErrorKind::Mpc, e)
    }
}

impl From<mpz_ot::kos::SenderError> for VerifierError {
    fn from(e: mpz_ot::kos::SenderError) -> Self {
        Self::new(ErrorKind::Mpc, e)
    }
}

impl From<mpz_ole::OLEError> for VerifierError {
    fn from(e: mpz_ole::OLEError) -> Self {
        Self::new(ErrorKind::Mpc, e)
    }
}

impl From<mpz_ot::kos::ReceiverError> for VerifierError {
    fn from(e: mpz_ot::kos::ReceiverError) -> Self {
        Self::new(ErrorKind::Mpc, e)
    }
}

impl From<mpz_garble::VmError> for VerifierError {
    fn from(e: mpz_garble::VmError) -> Self {
        Self::new(ErrorKind::Mpc, e)
    }
}

impl From<mpz_garble::protocol::deap::DEAPError> for VerifierError {
    fn from(e: mpz_garble::protocol::deap::DEAPError) -> Self {
        Self::new(ErrorKind::Mpc, e)
    }
}

impl From<mpz_garble::MemoryError> for VerifierError {
    fn from(e: mpz_garble::MemoryError) -> Self {
        Self::new(ErrorKind::Mpc, e)
    }
}

impl From<mpz_garble::VerifyError> for VerifierError {
    fn from(e: mpz_garble::VerifyError) -> Self {
        Self::new(ErrorKind::Mpc, e)
    }
}
