//! Utility functions.

use tlsn_core::{
    transcript::{SliceIdx, SubsequenceIdx, RX_TRANSCRIPT_ID, TX_TRANSCRIPT_ID},
    Direction,
};

/// Returns the value ID for each byte in the provided slice.
pub fn get_slice_ids(idx: &SliceIdx) -> impl Iterator<Item = String> + '_ {
    let id = match idx.direction {
        Direction::Sent => TX_TRANSCRIPT_ID,
        Direction::Received => RX_TRANSCRIPT_ID,
    };

    idx.range.clone().map(move |idx| format!("{}/{}", id, idx))
}

/// Returns the value ID for each byte in the provided subsequence.
pub fn get_subsequence_ids(idx: &SubsequenceIdx) -> impl Iterator<Item = String> + '_ {
    let id = match idx.direction() {
        Direction::Sent => TX_TRANSCRIPT_ID,
        Direction::Received => RX_TRANSCRIPT_ID,
    };

    idx.ranges()
        .iter()
        .map(move |idx| format!("{}/{}", id, idx))
}
