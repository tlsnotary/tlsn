//! Tooling for working with JSON data.

mod commitment;
mod proof;

pub use commitment::{JsonCommitmentBuilder, JsonCommitmentBuilderError};
pub use proof::{JsonProofBuilder, JsonProofBuilderError};

use spansy::json::JsonValue;

/// A JSON body
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonBody(pub(crate) JsonValue);
