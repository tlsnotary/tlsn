/// Methods performing various sanity checks on the [crate::verifier_doc::VerifierDocUnchecked]
use crate::verifier_doc::VerifierDocUnchecked;
use crate::{commitment::Range, Error};

/// Condition checked: at least one commitment is present
pub fn check_at_least_one_commitment_present(
    unchecked: &VerifierDocUnchecked,
) -> Result<(), Error> {
    if unchecked.commitments.is_empty() {
        return Err(Error::SanityCheckError);
    }
    Ok(())
}

/// Condition checked: commitments and openings have their ids incremental and ascending
pub fn check_commitment_and_opening_ids(unchecked: &VerifierDocUnchecked) -> Result<(), Error> {
    for i in 0..unchecked.commitments.len() {
        if !(unchecked.commitments[i].id == i && unchecked.commitment_openings[i].id == i) {
            return Err(Error::SanityCheckError);
        }
    }
    Ok(())
}

/// Condition checked: commitment count equals opening count
pub fn check_commitment_and_opening_count_equal(
    unchecked: &VerifierDocUnchecked,
) -> Result<(), Error> {
    if unchecked.commitments.len() != unchecked.commitment_openings.len() {
        return Err(Error::SanityCheckError);
    }
    Ok(())
}

/// Condition checked: ranges inside one commitment are non-empty, valid, ascending, non-overlapping, non-overflowing
pub fn check_ranges_inside_each_commitment(unchecked: &VerifierDocUnchecked) -> Result<(), Error> {
    for c in &unchecked.commitments {
        let len = c.ranges.len();
        // at least one range is expected
        if len == 0 {
            return Err(Error::SanityCheckError);
        }

        for r in &c.ranges {
            // ranges must be valid
            if r.end <= r.start {
                return Err(Error::SanityCheckError);
            }
        }

        // ranges must not overlap and must be ascending relative to each other
        for pair in c.ranges.windows(2) {
            if pair[1].start < pair[0].end {
                return Err(Error::SanityCheckError);
            }
        }

        // range bound must not be larger than u32
        if c.ranges[len - 1].end > (u32::MAX as usize) {
            return Err(Error::SanityCheckError);
        }
    }

    Ok(())
}

/// Condition checked: the length of each opening equals the amount of committed data in the ranges of the
/// corresponding commitment
/// Condition checked: the total amount of committed data is less than 1GB to prevent DoS
/// (this will cause the verifier to hash up to a max of 1GB * 128 = 128GB of labels)
pub fn check_commitment_sizes(unchecked: &VerifierDocUnchecked) -> Result<(), Error> {
    let mut total_committed = 0usize;

    for i in 0..unchecked.commitment_openings.len() {
        let expected = unchecked.commitment_openings[i].opening.len();
        let mut total_in_ranges = 0usize;
        for r in &unchecked.commitments[i].ranges {
            total_in_ranges += r.end - r.start;
        }
        if expected != total_in_ranges {
            return Err(Error::SanityCheckError);
        }
        total_committed += total_in_ranges;
        if total_committed > 1000000000 {
            return Err(Error::SanityCheckError);
        }
    }
    Ok(())
}

/// Condition checked: the amount of commitments is less that 1000
/// (searching for overlapping commitments in the naive way which we implemeted has quadratic cost,
/// hence this number shouldn't be too high to prevent DoS)
pub fn check_commitment_count(unchecked: &VerifierDocUnchecked) -> Result<(), Error> {
    if unchecked.commitments.len() >= 1000 {
        return Err(Error::SanityCheckError);
    }
    Ok(())
}

/// Condition checked: each Merkle tree index is both unique and also ascending between commitments
pub fn check_merkle_tree_indices(unchecked: &VerifierDocUnchecked) -> Result<(), Error> {
    let indices: Vec<usize> = unchecked
        .commitments
        .iter()
        .map(|c| c.merkle_tree_index)
        .collect();
    for pair in indices.windows(2) {
        if pair[0] >= pair[1] {
            return Err(Error::SanityCheckError);
        }
    }
    Ok(())
}

/// Makes sure that if two or more commitments contain overlapping ranges, the openings
/// corresponding to those ranges match exactly. Otherwise, if the openings don't match,
/// returns an error.
pub fn check_overlapping_openings(unchecked: &VerifierDocUnchecked) -> Result<(), Error> {
    // Note: using an existing lib to find multi-range overlap would incur the need to audit
    // that lib for correctness. Instead, since checking two range overlap is cheap, we are using
    // a naive way where we compare each range to all other ranges.
    // This naive way will have redundancy in computation but it will be easy to audit.

    for needle_c in unchecked.commitments.iter() {
        // Naming convention: we use the prefix "needle" to indicate the range that we are
        // looking for (and to indicate the associates offsets, commitments and openings).
        // Likewise the prefix "haystack" indicates _where_ we are searching.

        // byte offset in the opening. always positioned at the beginning of the range
        let mut needle_offset = 0usize;

        for needle_range in &needle_c.ranges {
            for haystack_c in unchecked.commitments.iter() {
                if needle_c.id == haystack_c.id {
                    // don't search within the same commitment
                    continue;
                }

                // byte offset in the opening. always positioned at the beginning of the range
                let mut haystack_offset = 0usize;
                // will be set to true when overlap is found
                let mut overlap_was_found = false;

                for haystack_range in &haystack_c.ranges {
                    match overlapping_range(needle_range, haystack_range) {
                        Some(ov_range) => {
                            // the bytesize of the overlap
                            let overlap_size = ov_range.end - ov_range.start;

                            // Find position (in the openings) from which the overlap starts. The
                            // offsets are already pointing to the beginning of the range, we just
                            // need to add the offset **within** the range.
                            let needle_ov_start =
                                needle_offset + (ov_range.start - needle_range.start);
                            let haystack_ov_start =
                                haystack_offset + (ov_range.start - haystack_range.start);

                            // get the openings which overlapped
                            // TODO: will later add a method get_opening_by_id()
                            let needle_o = &unchecked.commitment_openings[needle_c.id];
                            let haystack_o = &unchecked.commitment_openings[haystack_c.id];

                            if needle_o.opening[needle_ov_start..needle_ov_start + overlap_size]
                                != haystack_o.opening
                                    [haystack_ov_start..haystack_ov_start + overlap_size]
                            {
                                return Err(Error::OverlappingOpeningsDontMatch);
                            }

                            // even if set to true on prev iteration, it is ok to set again
                            overlap_was_found = true;
                        }
                        None => {
                            if overlap_was_found {
                                // An overlap was found in the previous range of the haystack
                                // but not in this range. There will be no overlap in any
                                // following haystack ranges of this commitment since all ranges
                                // within a commitment are sorted ascendingly relative to each other.
                                break;
                            }
                            // otherwise keep iterating
                        }
                    }

                    // advance the offset to the beginning of the next range
                    haystack_offset += haystack_range.end - haystack_range.start;
                }
            }
            // advance the offset to the beginning of the next range
            needle_offset += needle_range.end - needle_range.start;
        }
    }

    Ok(())
}

/// If two [Range]s overlap, returns the range containing the overlap
fn overlapping_range(a: &Range, b: &Range) -> Option<Range> {
    // find purported overlap's start and end
    let ov_start = std::cmp::max(a.start, b.start);
    let ov_end = std::cmp::min(a.end, b.end);
    if (ov_end - ov_start) < 1 {
        return None;
    } else {
        return Some(Range {
            start: ov_start,
            end: ov_end,
        });
    }
}
