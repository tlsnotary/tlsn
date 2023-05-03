use crate::{backend::BackendError, rand};
use std::{error::Error as StdError, fmt, time::SystemTimeError};
use tls_core::{
    msgs::enums::{AlertDescription, ContentType, HandshakeType},
    Error as CoreError,
};

/// rustls reports protocol errors using this type.
#[derive(Debug, PartialEq, Clone)]
pub enum Error {
    /// Error propagated from tls-core library
    CoreError(CoreError),

    /// Backend error
    BackendError(BackendError),

    /// We received a TLS message that isn't valid right now.
    /// `expect_types` lists the message types we can expect right now.
    /// `got_type` is the type we found.  This error is typically
    /// caused by a buggy TLS stack (the peer or this one), a broken
    /// network, or an attack.
    InappropriateMessage {
        /// Which types we expected
        expect_types: Vec<ContentType>,
        /// What type we received
        got_type: ContentType,
    },

    /// We received a TLS handshake message that isn't valid right now.
    /// `expect_types` lists the handshake message types we can expect
    /// right now.  `got_type` is the type we found.
    InappropriateHandshakeMessage {
        /// Which handshake type we expected
        expect_types: Vec<HandshakeType>,
        /// What handshake type we received
        got_type: HandshakeType,
    },

    /// We couldn't decrypt a message.  This is invariably fatal.
    DecryptError,

    /// We couldn't encrypt a message because it was larger than the allowed message size.
    /// This should never happen if the application is using valid record sizes.
    EncryptError,

    /// The peer sent us a syntactically incorrect TLS message.
    CorruptMessage,

    /// The peer sent us a TLS message with invalid contents.
    CorruptMessagePayload(ContentType),

    /// The peer didn't give us any certificates.
    NoCertificatesPresented,

    /// The certificate verifier doesn't support the given type of name.
    UnsupportedNameType,

    /// The peer doesn't support a protocol version/feature we require.
    /// The parameter gives a hint as to what version/feature it is.
    PeerIncompatibleError(String),

    /// The peer deviated from the standard TLS protocol.
    /// The parameter gives a hint where.
    PeerMisbehavedError(String),

    /// We received a fatal alert.  This means the peer is unhappy.
    AlertReceived(AlertDescription),

    /// We received an invalidly encoded certificate from the peer.
    InvalidCertificateEncoding,

    /// We received a certificate with invalid signature type.
    InvalidCertificateSignatureType,

    /// We received a certificate with invalid signature.
    InvalidCertificateSignature,

    /// We received a certificate which includes invalid data.
    InvalidCertificateData(String),

    /// The presented SCT(s) were invalid.
    InvalidSct(sct::Error),

    /// A catch-all error for unlikely errors.
    General(String),

    /// We failed to figure out what time it currently is.
    FailedToGetCurrentTime,

    /// We failed to acquire random bytes from the system.
    FailedToGetRandomBytes,

    /// This function doesn't work until the TLS handshake
    /// is complete.
    HandshakeNotComplete,

    /// The peer sent an oversized record/fragment.
    PeerSentOversizedRecord,

    /// An incoming connection did not support any known application protocol.
    NoApplicationProtocol,

    /// The `max_fragment_size` value supplied in configuration was too small,
    /// or too large.
    BadMaxFragmentSize,
}

fn join<T: fmt::Debug>(items: &[T]) -> String {
    items
        .iter()
        .map(|x| format!("{:?}", x))
        .collect::<Vec<String>>()
        .join(" or ")
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::CoreError(ref e) => {
                write!(f, "core error: {}", e)
            }
            Error::BackendError(ref e) => {
                write!(f, "backend error: {}", e)
            }
            Error::InappropriateMessage {
                ref expect_types,
                ref got_type,
            } => write!(
                f,
                "received unexpected message: got {:?} when expecting {}",
                got_type,
                join::<ContentType>(expect_types)
            ),
            Error::InappropriateHandshakeMessage {
                ref expect_types,
                ref got_type,
            } => write!(
                f,
                "received unexpected handshake message: got {:?} when expecting {}",
                got_type,
                join::<HandshakeType>(expect_types)
            ),
            Error::CorruptMessagePayload(ref typ) => {
                write!(f, "received corrupt message of type {:?}", typ)
            }
            Error::PeerIncompatibleError(ref why) => write!(f, "peer is incompatible: {}", why),
            Error::PeerMisbehavedError(ref why) => write!(f, "peer misbehaved: {}", why),
            Error::AlertReceived(ref alert) => write!(f, "received fatal alert: {:?}", alert),
            Error::InvalidCertificateEncoding => {
                write!(f, "invalid peer certificate encoding")
            }
            Error::InvalidCertificateSignatureType => {
                write!(f, "invalid peer certificate signature type")
            }
            Error::InvalidCertificateSignature => {
                write!(f, "invalid peer certificate signature")
            }
            Error::InvalidCertificateData(ref reason) => {
                write!(f, "invalid peer certificate contents: {}", reason)
            }
            Error::CorruptMessage => write!(f, "received corrupt message"),
            Error::NoCertificatesPresented => write!(f, "peer sent no certificates"),
            Error::UnsupportedNameType => write!(f, "presented server name type wasn't supported"),
            Error::DecryptError => write!(f, "cannot decrypt peer's message"),
            Error::EncryptError => write!(f, "cannot encrypt message"),
            Error::PeerSentOversizedRecord => write!(f, "peer sent excess record size"),
            Error::HandshakeNotComplete => write!(f, "handshake not complete"),
            Error::NoApplicationProtocol => write!(f, "peer doesn't support any known protocol"),
            Error::InvalidSct(ref err) => write!(f, "invalid certificate timestamp: {:?}", err),
            Error::FailedToGetCurrentTime => write!(f, "failed to get current time"),
            Error::FailedToGetRandomBytes => write!(f, "failed to get random bytes"),
            Error::BadMaxFragmentSize => {
                write!(f, "the supplied max_fragment_size was too small or large")
            }
            Error::General(ref err) => write!(f, "unexpected error: {}", err),
        }
    }
}

impl From<CoreError> for Error {
    #[inline]
    fn from(e: CoreError) -> Self {
        Self::CoreError(e)
    }
}

impl From<BackendError> for Error {
    #[inline]
    fn from(e: BackendError) -> Self {
        Self::BackendError(e)
    }
}

impl From<SystemTimeError> for Error {
    #[inline]
    fn from(_: SystemTimeError) -> Self {
        Self::FailedToGetCurrentTime
    }
}

impl StdError for Error {}

impl From<rand::GetRandomFailed> for Error {
    fn from(_: rand::GetRandomFailed) -> Self {
        Self::FailedToGetRandomBytes
    }
}

#[cfg(test)]
mod tests {
    use super::Error;

    #[test]
    fn smoke() {
        use sct;
        use tls_core::msgs::enums::{AlertDescription, ContentType, HandshakeType};

        let all = vec![
            Error::InappropriateMessage {
                expect_types: vec![ContentType::Alert],
                got_type: ContentType::Handshake,
            },
            Error::InappropriateHandshakeMessage {
                expect_types: vec![HandshakeType::ClientHello, HandshakeType::Finished],
                got_type: HandshakeType::ServerHello,
            },
            Error::CorruptMessage,
            Error::CorruptMessagePayload(ContentType::Alert),
            Error::NoCertificatesPresented,
            Error::PeerIncompatibleError("no tls1.2".to_string()),
            Error::PeerMisbehavedError("inconsistent something".to_string()),
            Error::AlertReceived(AlertDescription::ExportRestriction),
            Error::InvalidCertificateEncoding,
            Error::InvalidCertificateSignatureType,
            Error::InvalidCertificateSignature,
            Error::InvalidCertificateData("Data".into()),
            Error::InvalidSct(sct::Error::MalformedSct),
            Error::General("undocumented error".to_string()),
            Error::FailedToGetCurrentTime,
            Error::FailedToGetRandomBytes,
            Error::HandshakeNotComplete,
            Error::PeerSentOversizedRecord,
            Error::NoApplicationProtocol,
            Error::BadMaxFragmentSize,
        ];

        for err in all {
            println!("{:?}:", err);
            println!("  fmt '{}'", err);
        }
    }

    #[test]
    fn rand_error_mapping() {
        use super::rand;
        let err: Error = rand::GetRandomFailed.into();
        assert_eq!(err, Error::FailedToGetRandomBytes);
    }

    #[test]
    fn time_error_mapping() {
        use std::time::SystemTime;

        let time_error = SystemTime::UNIX_EPOCH
            .duration_since(SystemTime::now())
            .unwrap_err();
        let err: Error = time_error.into();
        assert_eq!(err, Error::FailedToGetCurrentTime);
    }
}
