use std::{error::Error, fmt};

use mpc_tls::MpcTlsError;

/// Error for [`Prover`](crate::prover::Prover).
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

    pub(crate) fn commit<E>(source: E) -> Self
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self::new(ErrorKind::Commit, source)
    }
}

#[derive(Debug)]
enum ErrorKind {
    Io,
    Mpc,
    Zk,
    Config,
    Commit,
}

impl fmt::Display for ProverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("prover error: ")?;

        match self.kind {
            ErrorKind::Io => f.write_str("io error")?,
            ErrorKind::Mpc => f.write_str("mpc error")?,
            ErrorKind::Zk => f.write_str("zk error")?,
            ErrorKind::Config => f.write_str("config error")?,
            ErrorKind::Commit => f.write_str("commit error")?,
        }

        if let Some(source) = &self.source {
            write!(f, " caused by: {source}")?;
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

impl From<tlsn_mux::ConnectionError> for ProverError {
    fn from(e: tlsn_mux::ConnectionError) -> Self {
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
