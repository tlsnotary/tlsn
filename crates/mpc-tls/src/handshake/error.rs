use crate::MpcTlsError;
use std::{error::Error as StdError, fmt, sync::Arc};
use tls_core::{
    Error as CoreError,
    msgs::enums::{AlertDescription, ContentType, HandshakeType},
};

/// TLS protocol errors are reported using this type.
#[derive(Debug, Clone)]
pub enum Error {
    /// Error propagated from tls-core library
    CoreError(CoreError),

    /// An error occurred in the MPC backend.
    BackendError(Arc<MpcTlsError>),

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

    /// The peer sent us a syntactically incorrect TLS message.
    CorruptMessage,

    /// The peer sent us a TLS message with invalid contents.
    CorruptMessagePayload(ContentType),

    /// The peer didn't give us any certificates.
    NoCertificatesPresented,

    /// The peer doesn't support a protocol version/feature we require.
    /// The parameter gives a hint as to what version/feature it is.
    PeerIncompatibleError(String),

    /// The peer deviated from the standard TLS protocol.
    /// The parameter gives a hint where.
    PeerMisbehavedError(String),

    /// We received a fatal alert.  This means the peer is unhappy.
    AlertReceived(AlertDescription),

    /// A catch-all error for unlikely errors.
    General(String),

    /// This function doesn't work until the TLS handshake
    /// is complete.
    HandshakeNotComplete,

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
            Self::CoreError(ref e) => {
                write!(f, "core error: {}", e)
            }
            Self::BackendError(ref e) => {
                write!(f, "backend error: {}", e)
            }
            Self::InappropriateMessage {
                ref expect_types,
                ref got_type,
            } => write!(
                f,
                "received unexpected message: got {:?} when expecting {}",
                got_type,
                join::<ContentType>(expect_types)
            ),
            Self::InappropriateHandshakeMessage {
                ref expect_types,
                ref got_type,
            } => write!(
                f,
                "received unexpected handshake message: got {:?} when expecting {}",
                got_type,
                join::<HandshakeType>(expect_types)
            ),
            Self::CorruptMessagePayload(ref typ) => {
                write!(f, "received corrupt message of type {:?}", typ)
            }
            Self::PeerIncompatibleError(ref why) => write!(f, "peer is incompatible: {}", why),
            Self::PeerMisbehavedError(ref why) => write!(f, "peer misbehaved: {}", why),
            Self::AlertReceived(ref alert) => write!(f, "received fatal alert: {:?}", alert),
            Self::CorruptMessage => write!(f, "received corrupt message"),
            Self::NoCertificatesPresented => write!(f, "peer sent no certificates"),
            Self::DecryptError => write!(f, "cannot decrypt peer's message"),
            Self::HandshakeNotComplete => write!(f, "handshake not complete"),
            Self::BadMaxFragmentSize => {
                write!(f, "the supplied max_fragment_size was too small or large")
            }
            Self::General(ref err) => write!(f, "unexpected error: {}", err),
        }
    }
}

impl From<CoreError> for Error {
    #[inline]
    fn from(e: CoreError) -> Self {
        Self::CoreError(e)
    }
}

impl From<MpcTlsError> for Error {
    #[inline]
    fn from(e: MpcTlsError) -> Self {
        Self::BackendError(Arc::new(e))
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::CoreError(e) => Some(e),
            Self::BackendError(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}
