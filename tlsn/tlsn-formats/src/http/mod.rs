//! Tooling for working with HTTP data.

mod body;
mod commitment;
mod parse;
mod proof;
mod verify;

pub use body::{Body, BodyCommitmentBuilder, BodyProofBuilder};
pub use commitment::{
    HttpCommitmentBuilder, HttpCommitmentBuilderError, HttpRequestCommitmentBuilder,
    HttpResponseCommitmentBuilder,
};
pub use parse::{parse_body, parse_requests, parse_responses, ParseError};
pub use proof::{HttpProofBuilder, HttpProofBuilderError};
pub use verify::{HttpRequestVerifier, HttpResponseVerifier, HttpVerifier};

/// An HTTP request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request(pub(crate) spansy::http::Request);

/// An HTTP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response(pub(crate) spansy::http::Response);
