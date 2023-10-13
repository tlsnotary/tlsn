use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use eyre::Report;
use std::error::Error;

use tlsn_notary::{NotaryConfigBuilderError, NotaryError};

#[derive(Debug, thiserror::Error)]
pub enum NotaryServerError {
    #[error(transparent)]
    Unexpected(#[from] Report),
    #[error("Failed to connect to prover: {0}")]
    Connection(String),
    #[error("Error occurred during notarization: {0}")]
    Notarization(Box<dyn Error + Send + 'static>),
    #[error("Invalid request from prover: {0}")]
    BadProverRequest(String),
}

impl From<NotaryError> for NotaryServerError {
    fn from(error: NotaryError) -> Self {
        Self::Notarization(Box::new(error))
    }
}

impl From<NotaryConfigBuilderError> for NotaryServerError {
    fn from(error: NotaryConfigBuilderError) -> Self {
        Self::Notarization(Box::new(error))
    }
}

/// Trait implementation to convert this error into an axum http response
impl IntoResponse for NotaryServerError {
    fn into_response(self) -> Response {
        match self {
            bad_request_error @ NotaryServerError::BadProverRequest(_) => {
                (StatusCode::BAD_REQUEST, bad_request_error.to_string()).into_response()
            }
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something wrong happened.",
            )
                .into_response(),
        }
    }
}
