use crate::{error::Error, Direction};
use blake3::Hasher;
use mpc_garble_core::{ChaChaEncoder, Encoder};
use std::{collections::HashSet, hash::Hash};

use crate::transcript::TranscriptSlice;
use mpc_circuits::types::ValueType;
use mpc_garble_core::EncodedValue;
use std::ops::Range;
use utils::bits::IterToBits;

/// Outputs a blake3 digest
pub fn blake3(data: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Returns true if all elements of the iterator are unique
pub fn has_unique_elements<T>(iter: T) -> bool
where
    T: IntoIterator,
    T::Item: Eq + Hash,
{
    let mut uniq = HashSet::new();
    iter.into_iter().all(move |x| uniq.insert(x))
}

/// Tries to merge `slices` and returns the resulting slices sorted ascendingly (note that even if no
/// merging was necessary, the `slices` will be returned sorted ascendingly).
/// Merging happens if slices overlap or are adjacent.
pub fn merge_slices(mut slices: Vec<TranscriptSlice>) -> Result<Vec<TranscriptSlice>, Error> {
    if slices.is_empty() {
        return Err(Error::InternalError);
    }

    // sort by the start bound of the slice's range
    slices.sort_by_key(|slice| slice.range().start);

    // `new_slices.len()` will always be <= `slices.len()`
    let mut new_slices = Vec::with_capacity(slices.len());

    // the current slice which we are trying to merge with the following slice
    let mut current = slices.remove(0);

    for slice in slices {
        match merged_slice(&current, &slice)? {
            // slices were not merged
            None => {
                new_slices.push(current);
                current = slice;
            }
            // set the resulting merged slice to be the current one and continue iteration
            Some(merged) => current = merged,
        }
    }
    new_slices.push(current);

    Ok(new_slices)
}

/// If two [TranscriptSlice]s overlap or are adjacent, return a new merged [TranscriptSlice]. It is
/// expected that both `a` and `b` have the exact same data in the overlapping range.
fn merged_slice(
    a: &TranscriptSlice,
    b: &TranscriptSlice,
) -> Result<Option<TranscriptSlice>, Error> {
    let merged_range = match merged_range(a.range(), b.range()) {
        // ranges neither overlap nor are adjacent
        None => return Ok(None),
        Some(range) => range,
    };

    // `merged_data` will contain data of the merged output slice
    let mut merged_data: Vec<u8> = vec![0u8; merged_range.len() as usize];

    // copy data from both slices into the output slice, ignoring for now the fact that
    // overlapping data will be overwritten
    let a_start_offset = (a.range().start - merged_range.start) as usize;
    merged_data[a_start_offset..a_start_offset + a.data().len()].copy_from_slice(a.data());

    let b_start_offset = (b.range().start - merged_range.start) as usize;
    merged_data[b_start_offset..b_start_offset + b.data().len()].copy_from_slice(b.data());

    // by checking that both a and b are subsets of the output slice, we make sure that a and b have
    // the exact same data in the overlapping range
    if &merged_data[a_start_offset..a_start_offset + a.data().len()] != a.data()
        || &merged_data[b_start_offset..b_start_offset + b.data().len()] != b.data()
    {
        return Err(Error::OverlappingSlicesDontMatch);
    }

    Ok(Some(TranscriptSlice::new(merged_range, merged_data)))
}

/// If two ranges overlap or are adjacent, returns a merged range
fn merged_range(a: &Range<u32>, b: &Range<u32>) -> Option<Range<u32>> {
    if !is_overlapping_or_adjacent(a, b) {
        return None;
    }
    Some(Range {
        start: std::cmp::min(a.start, b.start),
        end: std::cmp::max(a.end, b.end),
    })
}

/// Returns true if two ranges overlap or are adjacent
fn is_overlapping_or_adjacent(a: &Range<u32>, b: &Range<u32>) -> bool {
    // find purported overlap's start and end
    let ov_start = std::cmp::max(a.start, b.start);
    let ov_end = std::cmp::min(a.end, b.end);

    // Note that even if ranges do not overlap, they may still be adjacent if
    // ov_start == ov_end
    // (prevent overflow panic by casting into i64)
    ov_end as i64 - ov_start as i64 >= 0
}

/// Encodes the bytes located in ranges and returns a vec of encodings
/// It is only called internally when we know that
/// A) bytes.len() is equal to the sum of lengths of all ranges
/// B) ranges are non-overlapping and in ascending order
pub(crate) fn encode_bytes_in_ranges(
    encoder: &ChaChaEncoder,
    bytes: &[u8],
    ranges: &[Range<u32>],
    direction: &Direction,
) -> Vec<[u8; 16]> {
    // dummy id. In reality, the id will be generated differently
    let id = if direction == &Direction::Sent { 0 } else { 1 };
    let value_type = ValueType::new_array::<u8>(ranges.last().unwrap().end as usize);
    let full_encodings: EncodedValue<_> = encoder.encode_by_type(id, &value_type);

    // convert into bytes
    let full_encodings: Vec<[[u8; 16]; 2]> = full_encodings
        .iter_blocks()
        .map(|blocks| {
            [
                blocks[0].inner().to_be_bytes(),
                blocks[1].inner().to_be_bytes(),
            ]
        })
        .collect();

    // select only encodings located in ranges
    let mut full_encodings_in_ranges: Vec<[[u8; 16]; 2]> = Vec::new();
    for r in ranges {
        full_encodings_in_ranges
            .append(&mut full_encodings[(r.start * 8) as usize..(r.end * 8) as usize].to_vec())
    }

    // choose only active encodings
    full_encodings_in_ranges
        .into_iter()
        .zip(bytes.to_vec().into_lsb0_iter())
        .map(|(blocks, bit)| if bit { blocks[1] } else { blocks[0] })
        .collect()
}

mod tests {
    use super::*;

    #[test]
    fn test_has_unique_elements() {
        let unique: Vec<u32> = vec![1, 34, 3432, 5643];
        let not_unique: Vec<u32> = vec![1, 34, 3432, 5643, 34];
        assert!(has_unique_elements(unique));
        assert!(!has_unique_elements(not_unique));
    }

    #[test]
    // Expect merge_slices() to return a new vec of slices since some were merged
    fn test_merge_slices_new() {
        let _data = "some data for testing";

        let a_slice = TranscriptSlice::new(Range { start: 2, end: 4 }, "me".as_bytes().to_vec());
        let b_slice =
            TranscriptSlice::new(Range { start: 3, end: 10 }, "e data ".as_bytes().to_vec());
        let c_slice = TranscriptSlice::new(Range { start: 1, end: 5 }, "ome ".as_bytes().to_vec());
        let d_slice = TranscriptSlice::new(Range { start: 13, end: 15 }, " t".as_bytes().to_vec());

        // the first 3 slices will be merged into one slice
        let expected1 =
            TranscriptSlice::new(Range { start: 1, end: 10 }, "ome data ".as_bytes().to_vec());
        // the 4th one will not be merged
        let expected2 = d_slice.clone();

        assert_eq!(
            vec![expected1, expected2],
            merge_slices(vec![a_slice, b_slice, c_slice, d_slice]).unwrap()
        );
    }

    #[test]
    // Expect merge_slices() to return the same vec of slices since none were merged
    fn test_merge_slices_same() {
        let _data = "some data for testing";

        let a_slice = TranscriptSlice::new(Range { start: 2, end: 4 }, "me".as_bytes().to_vec());
        let b_slice = TranscriptSlice::new(Range { start: 9, end: 11 }, "fo".as_bytes().to_vec());
        let c_slice = TranscriptSlice::new(Range { start: 6, end: 7 }, "a".as_bytes().to_vec());
        let d_slice = TranscriptSlice::new(Range { start: 13, end: 15 }, " t".as_bytes().to_vec());

        // the slices will not be merged but will be sorted

        assert_eq!(
            vec![
                a_slice.clone(),
                c_slice.clone(),
                b_slice.clone(),
                d_slice.clone()
            ],
            merge_slices(vec![a_slice, b_slice, c_slice, d_slice]).unwrap()
        );
    }

    #[test]
    // Expect merge_slices() to return an error because data in overlapping slices does not match
    fn test_merge_slices_wrong_overlap_data() {
        let _data = "some data for testing";

        let a_slice = TranscriptSlice::new(Range { start: 2, end: 4 }, "me".as_bytes().to_vec());
        let b_slice =
            TranscriptSlice::new(Range { start: 3, end: 10 }, "e data ".as_bytes().to_vec());
        // this overlapping slice's data will not match
        let c_slice = TranscriptSlice::new(Range { start: 1, end: 5 }, "o?e ".as_bytes().to_vec());
        let d_slice = TranscriptSlice::new(Range { start: 13, end: 15 }, " t".as_bytes().to_vec());

        let err = merge_slices(vec![a_slice, b_slice, c_slice, d_slice]);
        assert_eq!(err.unwrap_err(), Error::OverlappingSlicesDontMatch);
    }
}
