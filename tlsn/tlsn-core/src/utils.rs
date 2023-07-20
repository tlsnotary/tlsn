use crate::error::Error;

use crate::transcript::TranscriptSlice;
use std::ops::Range;

#[cfg(feature = "tracing")]
use tracing::instrument;

/// Tries to merge `slices` and returns the resulting slices sorted ascendingly (note that even if no
/// merging was necessary, the `slices` will be returned sorted ascendingly).
/// Merging happens if slices overlap or are adjacent.
#[cfg_attr(feature = "tracing", instrument(level = "trace", skip(slices), err))]
pub(crate) fn merge_slices(
    mut slices: Vec<TranscriptSlice>,
) -> Result<Vec<TranscriptSlice>, Error> {
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
    let mut merged_data: Vec<u8> = vec![0u8; merged_range.len()];

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
    ov_end as i64 - ov_start as i64 >= 0
}

#[cfg(test)]
mod tests {
    use crate::{error::Error, utils::merge_slices, *};
    use std::ops::Range;

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
