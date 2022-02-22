use pop_mpc_core::ot::errors::{OTReceiverError, OTSenderError};
use std::fmt::{self, Display, Formatter};
use tokio::io::Error as IOError;

/// Errors that may occur when using AsyncOTSender
#[derive(Debug)]
pub enum AsyncOTSenderError {
    /// Error originating from OTSender core component
    CoreError(OTSenderError),
    /// Error originating from an IO Error
    IOError(IOError),
}

impl Display for AsyncOTSenderError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::CoreError(e) => write!(f, "{}", e),
            Self::IOError(e) => write!(f, "{}", e),
        }
    }
}

impl From<OTSenderError> for AsyncOTSenderError {
    fn from(e: OTSenderError) -> Self {
        Self::CoreError(e)
    }
}

/// Errors that may occur when using AsyncOTReceiver
#[derive(Debug)]
pub enum AsyncOTReceiverError {
    /// Error originating from OTSender core component
    CoreError(OTReceiverError),
    /// Error originating from an IO Error
    IOError(IOError),
}

impl Display for AsyncOTReceiverError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::CoreError(e) => write!(f, "{}", e),
            Self::IOError(e) => write!(f, "{}", e),
        }
    }
}

impl From<OTReceiverError> for AsyncOTReceiverError {
    fn from(e: OTReceiverError) -> Self {
        Self::CoreError(e)
    }
}
