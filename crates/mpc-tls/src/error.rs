use hmac_sha256::PrfError;
use key_exchange::KeyExchangeError;
use tls_backend::BackendError;

/// MPC-TLS error.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct MpcTlsError(#[from] ErrorRepr);

impl MpcTlsError {
    pub(crate) fn peer<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Peer(err.into()))
    }

    pub(crate) fn actor<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Actor(err.into()))
    }

    pub(crate) fn state<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::State(err.into()))
    }

    pub(crate) fn alloc<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Alloc(err.into()))
    }

    pub(crate) fn preprocess<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Preprocess(err.into()))
    }

    pub(crate) fn hs<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Handshake(err.into()))
    }

    pub(crate) fn record_layer<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::RecordLayer(err.into()))
    }

    pub(crate) fn other<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Other(err.into()))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("mpc-tls error: {0}")]
enum ErrorRepr {
    #[error("peer misbehaved")]
    Peer(Box<dyn std::error::Error + Send + Sync>),
    #[error("I/O error: {0}")]
    Io(std::io::Error),
    #[error("actor error: {0}")]
    Actor(Box<dyn std::error::Error + Send + Sync>),
    #[error("state error: {0}")]
    State(Box<dyn std::error::Error + Send + Sync>),
    #[error("allocation error: {0}")]
    Alloc(Box<dyn std::error::Error + Send + Sync>),
    #[error("preprocess error: {0}")]
    Preprocess(Box<dyn std::error::Error + Send + Sync>),
    #[error("handshake error: {0}")]
    Handshake(Box<dyn std::error::Error + Send + Sync>),
    #[error("record layer error: {0}")]
    RecordLayer(Box<dyn std::error::Error + Send + Sync>),
    #[error("other: {0}")]
    Other(Box<dyn std::error::Error + Send + Sync>),
}

impl From<std::io::Error> for MpcTlsError {
    fn from(value: std::io::Error) -> Self {
        MpcTlsError(ErrorRepr::Io(value))
    }
}

impl From<MpcTlsError> for BackendError {
    fn from(value: MpcTlsError) -> Self {
        BackendError::InternalError(value.to_string())
    }
}

impl From<KeyExchangeError> for MpcTlsError {
    fn from(value: KeyExchangeError) -> Self {
        MpcTlsError::hs(value)
    }
}

impl From<PrfError> for MpcTlsError {
    fn from(value: PrfError) -> Self {
        MpcTlsError::hs(value)
    }
}
