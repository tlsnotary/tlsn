//! Methods performing various validation checks on the [super::doc::UncheckedDoc]

use super::{
    commitment::{CommitmentOpening, CommitmentType, TranscriptRange},
    doc::UncheckedDoc,
    Error,
};

pub fn perform_checks(unchecked: &UncheckedDoc) -> Result<(), Error> {
    // Performs the following validation checks:
    //
    // - at least one commitment is present
    check_at_least_one_commitment_present(unchecked)?;

    // - commitment count equals opening count
    check_commitment_and_opening_count_equal(unchecked)?;

    // - each [commitment, opening] pair has their id incremental and ascending. The types of commitment
    //   and opening match.
    check_commitment_and_opening_pairs(unchecked)?;

    // - ranges inside one commitment are non-empty, valid, ascending, non-overlapping, non-overflowing
    check_ranges_inside_each_commitment(unchecked)?;

    // - the length of each opening equals the amount of committed data in the ranges of the
    //   corresponding commitment
    // - the total amount of committed data is less than 1GB to prevent DoS
    check_commitment_sizes(unchecked)?;

    // - the amount of commitments is less that 1000
    check_commitment_count(unchecked)?;

    // - overlapping openings must match exactly
    check_overlapping_openings(unchecked)?;

    // - each [merkle_tree_index] is both unique and also ascending between commitments
    check_merkle_tree_indices(unchecked)?;

    // - openings of LabelsBlake3 type must have their label seed match the label seed which the
    //   Notary signed
    check_labels_opening(unchecked)?;

    Ok(())
}

/// Condition checked: at least one commitment is present
fn check_at_least_one_commitment_present(unchecked: &UncheckedDoc) -> Result<(), Error> {
    if unchecked.commitments().is_empty() {
        return Err(Error::SanityCheckError(
            "check_at_least_one_commitment_present".to_string(),
        ));
    }
    Ok(())
}

/// Condition checked: each [commitment, opening] pair has their id incremental and ascending. The types
/// of commitment and opening match.
fn check_commitment_and_opening_pairs(unchecked: &UncheckedDoc) -> Result<(), Error> {
    // ids start from 0 an increment
    // (note that we already checked that commitment vec and opening vec have the same length)
    for i in 0..unchecked.commitment_openings().len() {
        let commitment = &unchecked.commitments()[i];
        let opening = &unchecked.commitment_openings()[i];

        // extract the opening variant
        let opening_variant = match opening {
            CommitmentOpening::LabelsBlake3(ref opening) => opening,
            // match any future types of opening here
            #[allow(unreachable_patterns)]
            _ => return Err(Error::NotImplemented),
        };

        // ids must match
        if !(commitment.id() == (i as u32) && opening_variant.id() == (i as u32)) {
            return Err(Error::SanityCheckError(
                "check_commitment_and_opening_ids".to_string(),
            ));
        }

        // types must match
        if matches!(commitment.typ(), &CommitmentType::labels_blake3)
            && !matches!(opening, CommitmentOpening::LabelsBlake3(_))
        {
            return Err(Error::SanityCheckError(
                "check_commitment_and_opening_ids".to_string(),
            ));
        }
    }

    Ok(())
}

/// Condition checked: commitment count equals opening count
fn check_commitment_and_opening_count_equal(unchecked: &UncheckedDoc) -> Result<(), Error> {
    if unchecked.commitments().len() != unchecked.commitment_openings().len() {
        return Err(Error::SanityCheckError(
            "check_commitment_and_opening_count_equal".to_string(),
        ));
    }
    Ok(())
}

/// Condition checked: ranges inside one commitment are non-empty, valid, ascending, non-overlapping
fn check_ranges_inside_each_commitment(unchecked: &UncheckedDoc) -> Result<(), Error> {
    for c in unchecked.commitments() {
        let len = c.ranges().len();
        // at least one range is expected
        if len == 0 {
            return Err(Error::SanityCheckError(
                "check_ranges_inside_each_commitment".to_string(),
            ));
        }

        for r in c.ranges() {
            // ranges must be valid
            if r.end() <= r.start() {
                return Err(Error::SanityCheckError(
                    "check_ranges_inside_each_commitment".to_string(),
                ));
            }
        }

        // ranges must not overlap and must be ascending relative to each other
        for pair in c.ranges().windows(2) {
            if pair[1].start() < pair[0].end() {
                return Err(Error::SanityCheckError(
                    "check_ranges_inside_each_commitment".to_string(),
                ));
            }
        }
    }

    Ok(())
}

/// Condition checked: the length of each opening equals the amount of committed data in the ranges of the
/// corresponding commitment
/// Condition checked: the total amount of committed data is less than 1GB to prevent DoS
/// (this will cause the verifier to hash up to a max of 1GB * 128 = 128GB of labels)
fn check_commitment_sizes(unchecked: &UncheckedDoc) -> Result<(), Error> {
    let mut total_committed = 0u64;

    for i in 0..unchecked.commitment_openings().len() {
        let opening = match unchecked.commitment_openings()[i] {
            CommitmentOpening::LabelsBlake3(ref opening) => opening,
            // match any future types of opening here
            #[allow(unreachable_patterns)]
            _ => return Err(Error::NotImplemented),
        };
        let expected = opening.opening().len() as u64;
        let mut total_in_ranges = 0u64;
        for r in unchecked.commitments()[i].ranges() {
            total_in_ranges += (r.end() - r.start()) as u64;
        }
        if expected != total_in_ranges {
            return Err(Error::SanityCheckError(
                "check_commitment_sizes".to_string(),
            ));
        }
        total_committed += total_in_ranges;
        if total_committed > 1000000000 {
            return Err(Error::SanityCheckError(
                "check_commitment_sizes".to_string(),
            ));
        }
    }
    Ok(())
}

/// Condition checked: the amount of commitments is less than 1000
/// (searching for overlapping commitments in the naive way which we implemented has quadratic cost,
/// hence this number shouldn't be too high to prevent DoS)
fn check_commitment_count(unchecked: &UncheckedDoc) -> Result<(), Error> {
    if unchecked.commitments().len() >= 1000 {
        return Err(Error::SanityCheckError(
            "check_commitment_count".to_string(),
        ));
    }
    Ok(())
}

/// Condition checked: each Merkle tree index is both unique and also ascending between commitments
fn check_merkle_tree_indices(unchecked: &UncheckedDoc) -> Result<(), Error> {
    let indices: Vec<u32> = unchecked
        .commitments()
        .iter()
        .map(|c| c.merkle_tree_index())
        .collect();
    for pair in indices.windows(2) {
        if pair[0] >= pair[1] {
            return Err(Error::SanityCheckError(
                "check_merkle_tree_indices".to_string(),
            ));
        }
    }
    Ok(())
}

/// Makes sure that if two or more commitments contain overlapping ranges, the openings
/// corresponding to those ranges match exactly. Otherwise, if the openings don't match,
/// returns an error.
fn check_overlapping_openings(unchecked: &UncheckedDoc) -> Result<(), Error> {
    // Note: using an existing lib to find multi-range overlap would incur the need to audit
    // that lib for correctness. Instead, since checking two range overlap is cheap, we are using
    // a naive way where we compare each range to all other ranges.
    // This naive way will have redundancy in computation but it will be easy to audit.

    for needle_c in unchecked.commitments().iter() {
        // Naming convention: we use the prefix "needle" to indicate the range that we are
        // looking for (and to indicate the associates offsets, commitments and openings).
        // Likewise the prefix "haystack" indicates _where_ we are searching.

        // byte offset in the opening; always positioned at the beginning of the range
        let mut needle_offset = 0u32;

        for needle_range in needle_c.ranges() {
            for haystack_c in unchecked.commitments().iter() {
                if needle_c.id() == haystack_c.id() {
                    // don't search within the same commitment
                    continue;
                }

                // byte offset in the opening; always positioned at the beginning of the range
                let mut haystack_offset = 0u32;
                // will be set to true when overlap is found
                let mut overlap_was_found = false;

                for haystack_range in haystack_c.ranges() {
                    match overlapping_range(needle_range, haystack_range)? {
                        Some(ov_range) => {
                            // the bytesize of the overlap
                            let overlap_size = ov_range.end() - ov_range.start();

                            // Find position (in the openings) from which the overlap starts. The
                            // offsets are already pointing to the beginning of the range, we just
                            // need to add the offset **within** the range.
                            let needle_ov_start =
                                needle_offset + (ov_range.start() - needle_range.start());
                            let haystack_ov_start =
                                haystack_offset + (ov_range.start() - haystack_range.start());

                            // get the openings which overlapped
                            let needle_o = &unchecked.commitment_openings()[needle_c.id() as usize];
                            let haystack_o =
                                &unchecked.commitment_openings()[haystack_c.id() as usize];

                            let needle_o_bytes = match needle_o {
                                CommitmentOpening::LabelsBlake3(opening) => opening.opening(),
                            };
                            let haystack_o_bytes = match haystack_o {
                                CommitmentOpening::LabelsBlake3(opening) => opening.opening(),
                            };

                            if needle_o_bytes[needle_ov_start as usize
                                ..(needle_ov_start + overlap_size) as usize]
                                != haystack_o_bytes[haystack_ov_start as usize
                                    ..(haystack_ov_start + overlap_size) as usize]
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
                    haystack_offset += haystack_range.end() - haystack_range.start();
                }
            }
            // advance the offset to the beginning of the next range
            needle_offset += needle_range.end() - needle_range.start();
        }
    }

    Ok(())
}

/// Condition checked: openings of LabelsBlake3Opening type must have their label seed match the
/// label seed which the Notary signed
fn check_labels_opening(unchecked: &UncheckedDoc) -> Result<(), Error> {
    for i in 0..unchecked.commitment_openings().len() {
        let opening = &unchecked.commitment_openings()[i];

        #[allow(irrefutable_let_patterns)]
        if let CommitmentOpening::LabelsBlake3(opening) = opening {
            if opening.label_seed() != unchecked.label_seed() {
                return Err(Error::SanityCheckError("check_labels_opening".to_string()));
            }
        }
    }

    Ok(())
}

/// If two ranges overlap, returns a new range containing the overlap
fn overlapping_range(
    a: &TranscriptRange,
    b: &TranscriptRange,
) -> Result<Option<TranscriptRange>, Error> {
    // find purported overlap's start and end
    let ov_start = std::cmp::max(a.start(), b.start());
    let ov_end = std::cmp::min(a.end(), b.end());
    if (ov_end - ov_start) < 1 {
        Ok(None)
    } else {
        let range = TranscriptRange::new(ov_start, ov_end)?;
        Ok(Some(range))
    }
}
