//! Tooling for working with JSON data.

mod commitment;
mod proof;

pub use commitment::{JsonCommitmentBuilder, JsonCommitmentBuilderError};
pub use proof::{JsonProofBuilder, JsonProofBuilderError};

use serde::{Deserialize, Serialize};
use spansy::{
    json::{JsonValue, JsonVisit},
    Spanned,
};
use utils::range::{RangeDifference, RangeSet, RangeUnion};

/// A JSON body
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonBody(pub(crate) JsonValue);

/// Computes all the public ranges of a JSON value.
///
/// Right now this is just the ranges of all the numbers and strings.
pub(crate) fn public_ranges(value: &JsonValue) -> RangeSet<usize> {
    #[derive(Default)]
    struct PrivateRanges {
        private_ranges: RangeSet<usize>,
    }

    // For now only numbers and strings are redactable.
    impl JsonVisit for PrivateRanges {
        fn visit_number(&mut self, node: &spansy::json::Number) {
            self.private_ranges = self.private_ranges.union(&node.span().range());
        }

        fn visit_string(&mut self, node: &spansy::json::String) {
            self.private_ranges = self.private_ranges.union(&node.span().range());
        }
    }

    let mut visitor = PrivateRanges::default();
    visitor.visit_value(value);

    value.span().range().difference(&visitor.private_ranges)
}
