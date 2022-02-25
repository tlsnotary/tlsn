use std::fmt::{self, Display, Formatter};

/// Errors that may occur when using BaseOTSender
#[derive(Debug)]
pub enum BaseOtSenderError {
    /// Base OT has not been setup
    NotSetup,
    /// Received invalid key from Base OT Receiver
    InvalidKey(Vec<u8>),
}

impl Display for BaseOtSenderError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::NotSetup => "OT Extension has not been setup".fmt(f),
            Self::InvalidKey(k) => write!(f, "Received invalid key from Receiver: {:?}", k),
        }
    }
}

/// Errors that may occur when using BaseOTReceiver
#[derive(Debug)]
pub enum BaseOtReceiverError {
    /// Base OT has not been setup
    NotSetup,
    /// Received invalid key from Base OT Sender
    InvalidKey(Vec<u8>),
}

impl Display for BaseOtReceiverError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::NotSetup => "OT Extension has not been setup".fmt(f),
            Self::InvalidKey(k) => write!(f, "Received invalid key from Sender: {:?}", k),
        }
    }
}

/// Errors that may occur when using OTSender
#[derive(Debug)]
pub enum OtSenderError {
    /// Error originating from Base OT
    BaseOTError(BaseOtReceiverError),
    /// Base OT has not been initialized
    BaseOTUninitialized,
    /// Base OT has not been setup
    BaseOTNotSetup,
    /// OT Extension has not been setup
    NotSetup,
}

impl Display for OtSenderError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::BaseOTError(e) => write!(f, "Base OT error: {:?}", e),
            Self::BaseOTUninitialized => "Base OT has not been initialized".fmt(f),
            Self::BaseOTNotSetup => "Base OT has not been setup".fmt(f),
            Self::NotSetup => "OT Extension has not been setup".fmt(f),
        }
    }
}

impl From<BaseOtReceiverError> for OtSenderError {
    fn from(e: BaseOtReceiverError) -> Self {
        Self::BaseOTError(e)
    }
}

/// Errors that may occur when using OTReceiver
#[derive(Debug)]
pub enum OtReceiverError {
    /// Error originating from Base OT
    BaseOTError(BaseOtSenderError),
    /// Base OT has not been initialized
    BaseOTUninitialized,
    /// Base OT has not been setup
    BaseOTNotSetup,
    /// OT Extension has not been setup
    NotSetup,
    /// Invalid Data
    InvalidData,
}

impl Display for OtReceiverError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::BaseOTError(e) => write!(f, "Base OT error: {:?}", e),
            Self::BaseOTUninitialized => "Base OT has not been initialized".fmt(f),
            Self::BaseOTNotSetup => "Base OT has not been setup".fmt(f),
            Self::NotSetup => "OT Extension has not been setup".fmt(f),
            Self::InvalidData => "Received invalid data from OT Sender".fmt(f),
        }
    }
}

impl From<BaseOtSenderError> for OtReceiverError {
    fn from(e: BaseOtSenderError) -> Self {
        Self::BaseOTError(e)
    }
}
