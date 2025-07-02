use mpz_memory_core::{
    MemoryExt, Vector,
    binary::{Binary, U8},
};
use mpz_vm_core::{Vm, VmError};
use rangeset::Intersection;
use tlsn_core::transcript::{Direction, Idx, PartialTranscript};

/// References to the application plaintext in the transcript.
#[derive(Debug, Default, Clone)]
pub(crate) struct TranscriptRefs {
    sent: Vec<Vector<U8>>,
    recv: Vec<Vector<U8>>,
}

impl TranscriptRefs {
    pub(crate) fn new(sent: Vec<Vector<U8>>, recv: Vec<Vector<U8>>) -> Self {
        Self { sent, recv }
    }

    /// Returns the sent plaintext references.
    pub(crate) fn sent(&self) -> &[Vector<U8>] {
        &self.sent
    }

    /// Returns the received plaintext references.
    pub(crate) fn recv(&self) -> &[Vector<U8>] {
        &self.recv
    }

    /// Returns VM references for the given direction and index, otherwise
    /// `None` if the index is out of bounds.
    pub(crate) fn get(&self, direction: Direction, idx: &Idx) -> Option<Vec<Vector<U8>>> {
        if idx.is_empty() {
            return Some(Vec::new());
        }

        let refs = match direction {
            Direction::Sent => &self.sent,
            Direction::Received => &self.recv,
        };

        // Computes the transcript range for each reference.
        let mut start = 0;
        let mut slice_iter = refs.iter().map(move |slice| {
            let out = (slice, start..start + slice.len());
            start += slice.len();
            out
        });

        let mut slices = Vec::new();
        let (mut slice, mut slice_range) = slice_iter.next()?;
        for range in idx.iter_ranges() {
            loop {
                if let Some(intersection) = slice_range.intersection(&range) {
                    let start = intersection.start - slice_range.start;
                    let end = intersection.end - slice_range.start;
                    slices.push(slice.get(start..end).expect("range should be in bounds"));
                }

                // Proceed to next range if the current slice extends beyond. Otherwise, proceed
                // to the next slice.
                if range.end <= slice_range.end {
                    break;
                } else {
                    (slice, slice_range) = slice_iter.next()?;
                }
            }
        }

        Some(slices)
    }
}

/// Decodes the transcript.
pub(crate) fn decode_transcript(
    vm: &mut dyn Vm<Binary>,
    sent: &Idx,
    recv: &Idx,
    refs: &TranscriptRefs,
) -> Result<(), VmError> {
    let sent_refs = refs.get(Direction::Sent, sent).expect("index is in bounds");
    let recv_refs = refs
        .get(Direction::Received, recv)
        .expect("index is in bounds");

    for slice in sent_refs.into_iter().chain(recv_refs) {
        // Drop the future, we don't need it.
        drop(vm.decode(slice)?);
    }

    Ok(())
}

/// Verifies a partial transcript.
pub(crate) fn verify_transcript(
    vm: &mut dyn Vm<Binary>,
    transcript: &PartialTranscript,
    refs: &TranscriptRefs,
) -> Result<(), InconsistentTranscript> {
    let sent_refs = refs
        .get(Direction::Sent, transcript.sent_authed())
        .expect("index is in bounds");
    let recv_refs = refs
        .get(Direction::Received, transcript.received_authed())
        .expect("index is in bounds");

    let mut authenticated_data = Vec::new();
    for data in sent_refs.into_iter().chain(recv_refs) {
        let plaintext = vm
            .get(data)
            .expect("reference is valid")
            .expect("plaintext is decoded");
        authenticated_data.extend_from_slice(&plaintext);
    }

    let mut purported_data = Vec::with_capacity(authenticated_data.len());
    for range in transcript.sent_authed().iter_ranges() {
        purported_data.extend_from_slice(&transcript.sent_unsafe()[range]);
    }

    for range in transcript.received_authed().iter_ranges() {
        purported_data.extend_from_slice(&transcript.received_unsafe()[range]);
    }

    if purported_data != authenticated_data {
        return Err(InconsistentTranscript {});
    }

    Ok(())
}

/// Error for [`verify_transcript`].
#[derive(Debug, thiserror::Error)]
#[error("inconsistent transcript")]
pub(crate) struct InconsistentTranscript {}

#[cfg(test)]
mod tests {
    use super::TranscriptRefs;
    use mpz_memory_core::{FromRaw, Slice, Vector, binary::U8};
    use rangeset::RangeSet;
    use std::ops::Range;
    use tlsn_core::transcript::{Direction, Idx};

    // TRANSCRIPT_REFS:
    //
    // 48..96 -> 6 slots
    // 112..176 -> 8 slots
    // 240..288 -> 6 slots
    // 352..392 -> 5 slots
    // 440..480 -> 5 slots
    const TRANSCRIPT_REFS: &[Range<usize>] = &[48..96, 112..176, 240..288, 352..392, 440..480];

    const IDXS: &[Range<usize>] = &[0..4, 5..10, 14..16, 16..28];

    // 1. Take slots 0..4,   4  slots -> 48..80 (4)
    // 2. Take slots 5..10,  5  slots -> 88..96 (1) + 112..144 (4)
    // 3. Take slots 14..16, 2  slots -> 240..256 (2)
    // 4. Take slots 16..28, 12 slots -> 256..288 (4) + 352..392 (5) + 440..464 (3)
    //
    // 5. Merge slots 240..256 and 256..288 => 240..288 and get EXPECTED_REFS
    const EXPECTED_REFS: &[Range<usize>] =
        &[48..80, 88..96, 112..144, 240..288, 352..392, 440..464];

    #[test]
    fn test_transcript_refs_get() {
        let transcript_refs: Vec<Vector<U8>> = TRANSCRIPT_REFS
            .iter()
            .cloned()
            .map(|range| Vector::from_raw(Slice::from_range_unchecked(range)))
            .collect();

        let transcript_refs = TranscriptRefs {
            sent: transcript_refs.clone(),
            recv: transcript_refs,
        };

        let vm_refs = transcript_refs
            .get(Direction::Sent, &idx_fixture())
            .unwrap();

        let expected_refs: Vec<Vector<U8>> = EXPECTED_REFS
            .iter()
            .cloned()
            .map(|range| Vector::from_raw(Slice::from_range_unchecked(range)))
            .collect();

        assert_eq!(
            vm_refs.len(),
            expected_refs.len(),
            "Length of actual and expected refs are not equal"
        );

        for (&expected, actual) in expected_refs.iter().zip(vm_refs) {
            assert_eq!(expected, actual);
        }
    }

    fn idx_fixture() -> Idx {
        let set = RangeSet::from(IDXS);
        Idx::builder().union(&set).build()
    }
}
