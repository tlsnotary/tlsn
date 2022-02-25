use pop_mpc_core::ot::errors::{OtReceiverError, OtSenderError};
use std::fmt::{self, Display, Formatter};
use tokio::io::Error as IOError;

/// Errors that may occur when using AsyncOTSender
#[derive(Debug)]
pub enum AsyncOtSenderError {
    /// Error originating from OTSender core component
    CoreError(OtSenderError),
    /// Error originating from an IO Error
    IOError(IOError),
    /// Received invalid message
    InvalidMessage,
}

impl Display for AsyncOtSenderError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::CoreError(e) => write!(f, "{}", e),
            Self::IOError(e) => write!(f, "{}", e),
            Self::InvalidMessage => "invalid message".fmt(f),
        }
    }
}

impl From<OtSenderError> for AsyncOtSenderError {
    fn from(e: OtSenderError) -> Self {
        Self::CoreError(e)
    }
}

impl From<IOError> for AsyncOtSenderError {
    fn from(e: IOError) -> Self {
        Self::IOError(e)
    }
}

/// Errors that may occur when using AsyncOtReceiver
#[derive(Debug)]
pub enum AsyncOtReceiverError {
    /// Error originating from OTSender core component
    CoreError(OtReceiverError),
    /// Error originating from an IO Error
    IOError(IOError),
    /// Received invalid message
    InvalidMessage,
}

impl Display for AsyncOtReceiverError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::CoreError(e) => write!(f, "{}", e),
            Self::IOError(e) => write!(f, "{}", e),
            Self::InvalidMessage => "invalid message".fmt(f),
        }
    }
}

impl From<OtReceiverError> for AsyncOtReceiverError {
    fn from(e: OtReceiverError) -> Self {
        Self::CoreError(e)
    }
}

impl From<IOError> for AsyncOtReceiverError {
    fn from(e: IOError) -> Self {
        Self::IOError(e)
    }
}
