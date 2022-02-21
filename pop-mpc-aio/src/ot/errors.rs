use std::fmt::{self, Display, Formatter};

/// Errors that may occur when using AsyncOTSender
#[derive(Debug)]
pub enum AsyncOTSenderError {
    /// Not Setup
    NotSetup,
}

impl Display for AsyncOTSenderError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            AsyncOTSenderError::NotSetup => "Tried to send before running setup".fmt(f),
        }
    }
}
