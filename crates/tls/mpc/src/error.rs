use std::{error::Error, fmt::Display};

use cipher::CipherError;
use tls_backend::BackendError;

/// MPC-TLS protocol error.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct MpcTlsError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    /// An unexpected state was encountered
    State(Box<dyn Error + Send + Sync + 'static>),
    /// Context error.
    Ctx(Box<dyn Error + Send + Sync + 'static>),
    /// IO related error
    Io(Box<dyn Error + Send + Sync + 'static>),
    /// An error occurred during key exchange
    KeyExchange(Box<dyn Error + Send + Sync + 'static>),
    /// An error occurred during PRF
    Prf(Box<dyn Error + Send + Sync + 'static>),
    /// An error occurred during encryption
    Encrypt(Box<dyn Error + Send + Sync + 'static>),
    /// An error occurred during decryption
    Decrypt(Box<dyn Error + Send + Sync + 'static>),
    /// An error related to configuration.
    Config(Box<dyn Error + Send + Sync + 'static>),
    /// Peer misbehaved somehow, perhaps maliciously.
    PeerMisbehaved(Box<dyn Error + Send + Sync + 'static>),
    /// Virtual machine error
    Vm(Box<dyn Error + Send + Sync + 'static>),
    /// Decoding error
    Decode(Box<dyn Error + Send + Sync + 'static>),
    /// Other error
    Other(Box<dyn Error + Send + Sync + 'static>),
}

impl MpcTlsError {
    pub(crate) fn state<E>(err: E) -> MpcTlsError
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::State(err.into()))
    }

    pub(crate) fn ctx<E>(err: E) -> MpcTlsError
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Ctx(err.into()))
    }

    pub(crate) fn io<E>(err: E) -> MpcTlsError
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Io(err.into()))
    }

    pub(crate) fn key_exchange<E>(err: E) -> MpcTlsError
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::KeyExchange(err.into()))
    }

    pub(crate) fn prf<E>(err: E) -> MpcTlsError
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Prf(err.into()))
    }

    pub(crate) fn encrypt<E>(err: E) -> MpcTlsError
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Encrypt(err.into()))
    }

    pub(crate) fn decrypt<E>(err: E) -> MpcTlsError
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Decrypt(err.into()))
    }

    pub(crate) fn config<E>(err: E) -> MpcTlsError
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Config(err.into()))
    }

    pub(crate) fn peer<E>(err: E) -> MpcTlsError
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::PeerMisbehaved(err.into()))
    }

    pub(crate) fn vm<E>(err: E) -> MpcTlsError
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Vm(err.into()))
    }

    pub(crate) fn decode<E>(err: E) -> MpcTlsError
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Decode(err.into()))
    }

    pub(crate) fn other<E>(err: E) -> MpcTlsError
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::other(err.into()))
    }
}
