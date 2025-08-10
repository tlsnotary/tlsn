#![no_main]

use libfuzzer_sys::fuzz_target;
use tlsn_core::transcript::{CompressedPartialTranscript, PartialTranscript, Idx, Transcript};
use arbitrary::Unstructured;
use rangeset::RangeSet;

fuzz_target!(|data: &[u8]| {
    let mut fuzz_input = Unstructured::new(data);

    // Fuzz lengths for the full transcript
    let sent_len: usize = fuzz_input.int_in_range(0..=1024).unwrap_or(0);
    let recv_len: usize = fuzz_input.int_in_range(0..=1024).unwrap_or(0);

    // Create base transcript (filled with zeros)
    let transcript = Transcript::new(vec![0; sent_len], vec![0; recv_len]);

    // Fuzz authenticated ranges for sent and received
    let mut sent_authed_ranges = Vec::new();
    let mut recv_authed_ranges = Vec::new();

    // Fuzz number of ranges
    let sent_range_count = fuzz_input.int_in_range(0..=10).unwrap_or(0);
    for _ in 0..sent_range_count {
        let start: usize = fuzz_input.arbitrary().unwrap_or(0) % sent_len.saturating_add(1);
        let end: usize = fuzz_input.arbitrary().unwrap_or(0) % sent_len.saturating_add(1);
        if start < end && end <= sent_len {
            sent_authed_ranges.push(start..end);
        }
    }

    let recv_range_count = fuzz_input.int_in_range(0..=10).unwrap_or(0);
    for _ in 0..recv_range_count {
        let start: usize = fuzz_input.arbitrary().unwrap_or(0) % recv_len.saturating_add(1);
        let end: usize = fuzz_input.arbitrary().unwrap_or(0) % recv_len.saturating_add(1);
        if start < end && end <= recv_len {
            recv_authed_ranges.push(start..end);
        }
    }

    // Build Idx from ranges
    let sent_authed_idx = Idx::new(RangeSet::new(&sent_authed_ranges));
    let received_authed_idx = Idx::new(RangeSet::new(&recv_authed_ranges));

    // Use the public API to create PartialTranscript with authenticated indices
    let partial_transcript = transcript.to_partial(sent_authed_idx, received_authed_idx);

    // Convert to CompressedPartialTranscript using public `From`
    let compressed: CompressedPartialTranscript = partial_transcript.into();

    // Serialize and deserialize
    if let Ok(serialized) = bincode::serialize(&compressed) {
        let _ = bincode::deserialize::<CompressedPartialTranscript>(&serialized);
    }
});