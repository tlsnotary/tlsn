use std::fmt::{self, Display, Formatter};

/// Errors that may occur when using OTSender
#[derive(Debug)]
pub enum OTSenderError {
    /// Base OT has not been initialized
    BaseOTUninitialized,
    /// Base OT has not been setup
    BaseOTNotSetup,
    /// OT Extension has not been setup
    NotSetup,
}

impl Display for OTSenderError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            OTSenderError::BaseOTUninitialized => "Base OT has not been initialized".fmt(f),
            OTSenderError::BaseOTNotSetup => "Base OT has not been setup".fmt(f),
            OTSenderError::NotSetup => "OT Extension has not been setup".fmt(f),
        }
    }
}

/// Errors that may occur when using OTReceiver
#[derive(Debug)]
pub enum OTReceiverError {
    /// Base OT has not been initialized
    BaseOTUninitialized,
    /// Base OT has not been setup
    BaseOTNotSetup,
    /// OT Extension has not been setup
    NotSetup,
}

impl Display for OTReceiverError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            OTReceiverError::BaseOTUninitialized => "Base OT has not been initialized".fmt(f),
            OTReceiverError::BaseOTNotSetup => "Base OT has not been setup".fmt(f),
            OTReceiverError::NotSetup => "OT Extension has not been setup".fmt(f),
        }
    }
}
