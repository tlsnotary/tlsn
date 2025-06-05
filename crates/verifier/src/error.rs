use mpc_tls::MpcTlsError;
use std::{error::Error, fmt};
use tlsn_common::{encoding::EncodingError, zk_aes_ctr::ZkAesCtrError};

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

    pub(crate) fn mpc<E>(source: E) -> Self
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self::new(ErrorKind::Mpc, source)
    }

    pub(crate) fn zk<E>(source: E) -> Self
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self::new(ErrorKind::Zk, source)
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
    Zk,
    Commit,
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
            ErrorKind::Zk => f.write_str("zk error")?,
            ErrorKind::Commit => f.write_str("commit error")?,
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

impl From<ZkAesCtrError> for VerifierError {
    fn from(e: ZkAesCtrError) -> Self {
        Self::new(ErrorKind::Zk, e)
    }
}

impl From<EncodingError> for VerifierError {
    fn from(e: EncodingError) -> Self {
        Self::new(ErrorKind::Commit, e)
    }
}
