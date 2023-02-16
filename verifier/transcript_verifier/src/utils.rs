use crate::{
    commitment::TranscriptRange, label_encoder::ChaChaEncoder,
    verified_transcript::TranscriptSlice, Error, HashCommitment, LabelSeed,
};
use blake3::Hasher;

/// Given a `substring` and its byte `ranges` within a larger string, computes a (`salt`ed) commitment
/// to the garbled circuit labels. The labels are derived from a PRG `seed`.
/// `ranges` are ordered ascendingly relative to each other.
pub(crate) fn compute_label_commitment(
    substring: &[u8],
    ranges: &[TranscriptRange],
    seed: &LabelSeed,
    salt: &[u8],
) -> Result<HashCommitment, Error> {
    let mut enc = ChaChaEncoder::new(*seed);

    // making a copy of the substring because we will be drain()ing it
    let mut bytestring = substring.to_vec();

    let mut hasher = Hasher::new();
    for r in ranges {
        let range_size = (r.end() - r.start()) as u64;
        let bytes_in_range: Vec<u8> = bytestring.drain(0..range_size as usize).collect();

        // convert bytes in the range into bits in lsb0 order
        let bits = u8vec_to_boolvec(&bytes_in_range);
        let mut bits_iter = bits.into_iter();

        // derive as many label pairs as there are bits in the range
        for i in r.start() * 8..r.end() * 8 {
            let label_pair = enc.encode(i as usize);
            let bit = match bits_iter.next() {
                Some(bit) => bit,
                // should never happen since this method is only called with ranges validated
                // to correspond to the size of the substring
                None => return Err(Error::InternalError),
            };
            let active_label = if bit { label_pair[1] } else { label_pair[0] };

            hasher.update(&active_label.inner().to_be_bytes());
        }
    }
    // add salt
    hasher.update(salt);
    Ok(hasher.finalize().into())
}

/// Converts a u8 vec into an lsb0 bool vec
#[inline]
pub(crate) fn u8vec_to_boolvec(v: &[u8]) -> Vec<bool> {
    let mut bv = Vec::with_capacity(v.len() * 8);
    for byte in v.iter() {
        for i in 0..8 {
            bv.push(((byte >> i) & 1) != 0);
        }
    }
    bv
}

/// Outputs blake3 digest
pub(crate) fn blake3(data: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// If two ranges overlap, returns a new range containing the overlap
pub(crate) fn overlapping_range(
    a: &TranscriptRange,
    b: &TranscriptRange,
) -> Option<TranscriptRange> {
    // find purported overlap's start and end
    let ov_start = std::cmp::max(a.start(), b.start());
    let ov_end = std::cmp::min(a.end(), b.end());
    // (prevent overflow panic by casting into i64)
    if (ov_end as i64 - ov_start as i64) < 1 {
        None
    } else {
        let range =
            TranscriptRange::new(ov_start, ov_end).expect("start bound must be > end bound");
        Some(range)
    }
}

/// Returns true if two ranges overlap or are adjacent
fn is_overlapping_or_adjacent(a: &TranscriptRange, b: &TranscriptRange) -> bool {
    // find purported overlap's start and end
    let ov_start = std::cmp::max(a.start(), b.start());
    let ov_end = std::cmp::min(a.end(), b.end());

    // Note that even if ranges do not overlap, they may still be adjacent if
    // ov_start == ov_end
    // (prevent overflow panic by casting into i64)
    ov_end as i64 - ov_start as i64 >= 0
}

/// If two ranges overlap or are adjacent, returns a merged range
fn merged_range(a: &TranscriptRange, b: &TranscriptRange) -> Option<TranscriptRange> {
    if !is_overlapping_or_adjacent(a, b) {
        return None;
    }
    // overlap detected
    let merged_start = std::cmp::min(a.start(), b.start());
    let merged_end = std::cmp::max(a.end(), b.end());

    Some(TranscriptRange::new(merged_start, merged_end).expect("start bound must be > end bound"))
}

/// If two [TranscriptSlice]s overlap or are adjacent, return a new merged [TranscriptSlice]
fn merged_slice(a: &TranscriptSlice, b: &TranscriptSlice) -> Option<TranscriptSlice> {
    let merged_range = match merged_range(a.range(), b.range()) {
        None => return None,
        Some(range) => range,
    };

    // Find which range's start bound is lower. If both have the same start bound, we arbitrarily
    // choose range `a` as the lower range.
    let (lower_range, higher_range) = if a.range().start() <= b.range().start() {
        (a, b)
    } else {
        (b, a)
    };

    // merged_data contains data from merged ranges. If ranges overlap, the ovelapping data will be
    // included only once.
    // (note that we already checked earlier that overlapping parts of the ranges match
    // exactly)
    let mut merged_data: Vec<u8> = lower_range.data().clone();
    if higher_range.range().end() > lower_range.range().end() {
        // find the data from `higher_range` which was not covered by `lower_range`
        let not_covered_count = (higher_range.range().end() - lower_range.range().end()) as usize;
        let higher_range_len = higher_range.data().len();
        let not_covered_data =
            &higher_range.data().clone()[higher_range_len - not_covered_count..higher_range_len];
        // append the data
        merged_data.extend_from_slice(not_covered_data);
    }

    Some(TranscriptSlice::new(merged_range, merged_data))
}

/// Merges sorted `slices` if they overlap or are adjacent and returns the resulting slices.
/// This function is always called with sorted non-empty `slices`.
pub(crate) fn merge_sorted_slices(mut slices: Vec<TranscriptSlice>) -> Vec<TranscriptSlice> {
    // will only panic is there is an internal error
    assert!(!slices.is_empty());

    // `new_slices.len()` will always be <= `slices.len()`
    let mut new_slices = Vec::with_capacity(slices.len());

    // the current slice which we are trying to merge with the following slice
    let mut current = slices.remove(0);

    for slice in slices {
        match merged_slice(&current, &slice) {
            None => {
                new_slices.push(current);
                current = slice;
            }
            // set the merged slice to be the current one and continue iteration
            Some(merged) => current = merged,
        }
    }
    new_slices.push(current);

    new_slices
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test::{bytes_in_ranges, DEFAULT_PLAINTEXT};

    #[test]
    // Expect u8vec_to_boolvec to output the expected result
    fn test_u8vec_to_boolvec() {
        let mut u = vec![false; 8];
        u[0] = true;
        u[2] = true;
        u[4] = true;
        u[7] = true;
        let res = u8vec_to_boolvec(&149u8.to_be_bytes());
        assert_eq!(res, u);

        let mut u = vec![false; 16];
        u[0] = true;
        u[9] = true;
        let res = u8vec_to_boolvec(&258u16.to_be_bytes());
        assert_eq!(res, u);
    }

    #[test]
    // Expect overlapping_range() to find an overlap
    fn test_overlapping_range_found() {
        let a = TranscriptRange::new(2, 20).unwrap();
        let b = TranscriptRange::new(10, 30).unwrap();
        let expected_overlap = TranscriptRange::new(10, 20).unwrap();

        assert_eq!(expected_overlap, overlapping_range(&a, &b).unwrap());
    }

    #[test]
    // Expect overlapping_range() to NOT find an overlap for two adjacent ranges
    fn test_overlapping_range_not_found() {
        let a = TranscriptRange::new(2, 20).unwrap();
        let b = TranscriptRange::new(20, 30).unwrap();

        assert!(overlapping_range(&a, &b).is_none());
    }

    #[test]
    // Expect is_overlapping_or_adjacent() to return true for adjacent and for overlapping ranges
    fn test_is_overlapping_or_adjacent_true() {
        let a = TranscriptRange::new(2, 20).unwrap();
        let b = TranscriptRange::new(20, 30).unwrap();
        assert!(is_overlapping_or_adjacent(&a, &b));

        let a = TranscriptRange::new(2, 20).unwrap();
        let b = TranscriptRange::new(10, 30).unwrap();
        assert!(is_overlapping_or_adjacent(&a, &b));
    }

    #[test]
    // Expect is_overlapping_or_adjacent() to return false for non-adjacent ranges
    fn test_is_overlapping_or_adjacent_false() {
        let a = TranscriptRange::new(2, 20).unwrap();
        let b = TranscriptRange::new(21, 30).unwrap();
        assert!(!is_overlapping_or_adjacent(&a, &b));
    }

    #[test]
    // Expect merged_range() to return the expected merged range
    fn test_merged_range_some() {
        let a = TranscriptRange::new(2, 20).unwrap();
        let b = TranscriptRange::new(10, 30).unwrap();
        let expected_merged = TranscriptRange::new(2, 30).unwrap();

        assert_eq!(expected_merged, merged_range(&a, &b).unwrap());
    }

    #[test]
    // Expect merged_range() to return None since ranges are neither adjacent nor overlapping
    fn test_merged_range_none() {
        let a = TranscriptRange::new(2, 3).unwrap();
        let b = TranscriptRange::new(10, 30).unwrap();

        assert!(merged_range(&a, &b).is_none());
    }

    #[test]
    // Expect merged_slice() to return the expected merged slice
    fn test_merged_slice_some() {
        let a = TranscriptRange::new(2, 20).unwrap();
        let a_bytes = bytes_in_ranges(&DEFAULT_PLAINTEXT, &[a.clone()]);
        let a_slice = TranscriptSlice::new(a, a_bytes);

        let b = TranscriptRange::new(10, 30).unwrap();
        let b_bytes = bytes_in_ranges(&DEFAULT_PLAINTEXT, &[b.clone()]);
        let b_slice = TranscriptSlice::new(b, b_bytes);

        let expected_range = TranscriptRange::new(2, 30).unwrap();
        let expected_bytes = bytes_in_ranges(&DEFAULT_PLAINTEXT, &[expected_range.clone()]);
        let expected_slice = TranscriptSlice::new(expected_range, expected_bytes);

        assert_eq!(expected_slice, merged_slice(&a_slice, &b_slice).unwrap());
    }

    #[test]
    // Expect merged_slice() to return None
    fn test_merged_slice_none() {
        let a = TranscriptRange::new(2, 9).unwrap();
        let a_bytes = bytes_in_ranges(&DEFAULT_PLAINTEXT, &[a.clone()]);
        let a_slice = TranscriptSlice::new(a, a_bytes);

        let b = TranscriptRange::new(10, 30).unwrap();
        let b_bytes = bytes_in_ranges(&DEFAULT_PLAINTEXT, &[b.clone()]);
        let b_slice = TranscriptSlice::new(b, b_bytes);

        assert!(merged_slice(&a_slice, &b_slice).is_none());
    }

    #[test]
    // Expect merge_sorted_slices to return a new vec of slices since some were merged
    fn test_merge_sorted_slices_new() {
        // create some slices sorted ascendingly by the start bound
        let a = TranscriptRange::new(2, 20).unwrap();
        let a_bytes = bytes_in_ranges(&DEFAULT_PLAINTEXT, &[a.clone()]);
        let a_slice = TranscriptSlice::new(a, a_bytes);

        let b = TranscriptRange::new(10, 30).unwrap();
        let b_bytes = bytes_in_ranges(&DEFAULT_PLAINTEXT, &[b.clone()]);
        let b_slice = TranscriptSlice::new(b, b_bytes);

        let c = TranscriptRange::new(20, 25).unwrap();
        let c_bytes = bytes_in_ranges(&DEFAULT_PLAINTEXT, &[c.clone()]);
        let c_slice = TranscriptSlice::new(c, c_bytes);

        let d = TranscriptRange::new(32, 40).unwrap();
        let d_bytes = bytes_in_ranges(&DEFAULT_PLAINTEXT, &[d.clone()]);
        let d_slice = TranscriptSlice::new(d, d_bytes);

        // the first 3 slices will be merged
        let expected1 = TranscriptRange::new(2, 30).unwrap();
        let expected1_bytes = bytes_in_ranges(&DEFAULT_PLAINTEXT, &[expected1.clone()]);
        let expected1_slice = TranscriptSlice::new(expected1, expected1_bytes);

        // the 4th one will not be merged
        let expected2_slice = d_slice.clone();

        assert_eq!(
            vec![expected1_slice, expected2_slice],
            merge_sorted_slices(vec![a_slice, b_slice, c_slice, d_slice])
        );
    }

    #[test]
    // Expect merge_sorted_slices to return the same vec of slices since none were merged
    fn test_merge_sorted_slices_same() {
        // create some slices sorted ascendingly by the start bound
        let a = TranscriptRange::new(2, 9).unwrap();
        let a_bytes = bytes_in_ranges(&DEFAULT_PLAINTEXT, &[a.clone()]);
        let a_slice = TranscriptSlice::new(a, a_bytes);

        let b = TranscriptRange::new(10, 16).unwrap();
        let b_bytes = bytes_in_ranges(&DEFAULT_PLAINTEXT, &[b.clone()]);
        let b_slice = TranscriptSlice::new(b, b_bytes);

        let c = TranscriptRange::new(20, 25).unwrap();
        let c_bytes = bytes_in_ranges(&DEFAULT_PLAINTEXT, &[c.clone()]);
        let c_slice = TranscriptSlice::new(c, c_bytes);

        let d = TranscriptRange::new(32, 40).unwrap();
        let d_bytes = bytes_in_ranges(&DEFAULT_PLAINTEXT, &[d.clone()]);
        let d_slice = TranscriptSlice::new(d, d_bytes);

        assert_eq!(
            vec![
                a_slice.clone(),
                b_slice.clone(),
                c_slice.clone(),
                d_slice.clone()
            ],
            merge_sorted_slices(vec![a_slice, b_slice, c_slice, d_slice])
        );
    }
}
