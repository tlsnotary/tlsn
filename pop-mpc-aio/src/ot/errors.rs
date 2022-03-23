use pop_mpc_core::ot::errors::{OtReceiverCoreError, OtSenderCoreError};
use std::fmt::{self, Display, Formatter};
use tokio::io::Error as IOError;

/// Errors that may occur when using AsyncOTSender
#[derive(Debug)]
pub enum OtSenderError {
    /// Error originating from OTSender core component
    CoreError(OtSenderCoreError),
    /// Error originating from an IO Error
    IOError(IOError),
    /// Received invalid message
    MalformedMessage,
}

impl Display for OtSenderError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::CoreError(e) => write!(f, "{}", e),
            Self::IOError(e) => write!(f, "{}", e),
            Self::MalformedMessage => "malformed message".fmt(f),
        }
    }
}

impl From<OtSenderCoreError> for OtSenderError {
    fn from(e: OtSenderCoreError) -> Self {
        Self::CoreError(e)
    }
}

impl From<IOError> for OtSenderError {
    fn from(e: IOError) -> Self {
        Self::IOError(e)
    }
}

/// Errors that may occur when using AsyncOtReceiver
#[derive(Debug)]
pub enum OtReceiverError {
    /// Error originating from OTSender core component
    CoreError(OtReceiverCoreError),
    /// Error originating from an IO Error
    IOError(IOError),
    /// Received invalid message
    MalformedMessage,
}

impl Display for OtReceiverError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::CoreError(e) => write!(f, "{}", e),
            Self::IOError(e) => write!(f, "{}", e),
            Self::MalformedMessage => "invalid message".fmt(f),
        }
    }
}

impl From<OtReceiverCoreError> for OtReceiverError {
    fn from(e: OtReceiverCoreError) -> Self {
        Self::CoreError(e)
    }
}

impl From<IOError> for OtReceiverError {
    fn from(e: IOError) -> Self {
        Self::IOError(e)
    }
}
