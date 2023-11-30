use tls_core::msgs::enums::{ContentType, NamedGroup};

use crate::msg::MpcTlsMessageError;

/// An error type for this crate
#[allow(missing_docs)]
#[derive(Debug, thiserror::Error)]
pub enum MpcTlsError {
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error(transparent)]
    MuxerError(#[from] utils_aio::mux::MuxerError),
    #[error(transparent)]
    VmError(#[from] mpz_garble::VmError),
    #[error(transparent)]
    KeyExchangeError(#[from] key_exchange::KeyExchangeError),
    #[error(transparent)]
    PrfError(#[from] hmac_sha256::PrfError),
    #[error(transparent)]
    AeadError(#[from] aead::AeadError),
    #[error("no committed message")]
    NoCommittedMessage,
    #[error("unexpected content type")]
    UnexpectedContentType(ContentType),
    #[error("invalid message length: {0}")]
    InvalidMessageLength(usize),
    #[error("maximum transcript length exceeded: {} > {}", .0, .1)]
    MaxTranscriptLengthExceeded(usize, usize),
    #[error("unexpected sequence number: {0}")]
    UnexpectedSequenceNumber(u64),
    #[error("not set up")]
    NotSetUp,
    #[error("server key not set")]
    ServerKeyNotSet,
    #[error("server cert not set")]
    ServerCertNotSet,
    #[error("server random not set")]
    ServerRandomNotSet,
    #[error("server kx details not set")]
    ServerKxDetailsNotSet,
    #[error("unsupported curve group: {0:?}")]
    UnsupportedCurveGroup(NamedGroup),
    #[error("invalid server key")]
    InvalidServerKey,
    #[error("invalid handshake hash")]
    InvalidHandshakeHash(Vec<u8>),
    #[error("received fatal alert")]
    ReceivedFatalAlert,
    #[error("payload decoding error")]
    PayloadDecodingError,
    #[error("leader closed the connection abruptly")]
    LeaderClosedAbruptly,
}

impl From<MpcTlsMessageError> for MpcTlsError {
    fn from(err: MpcTlsMessageError) -> Self {
        std::io::Error::new(std::io::ErrorKind::InvalidData, err).into()
    }
}
