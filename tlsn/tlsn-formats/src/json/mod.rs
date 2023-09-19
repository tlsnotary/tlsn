//! Tooling for working with JSON data.

mod commitment;
mod proof;
mod verify;

pub use commitment::{JsonCommitmentBuilder, JsonCommitmentBuilderError};
pub use proof::{JsonProofBuilder, JsonProofBuilderError};
pub use verify::JsonVerifier;

use spansy::json::JsonValue;

/// A JSON body
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonBody(pub(crate) JsonValue);
