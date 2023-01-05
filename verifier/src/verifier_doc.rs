use crate::commitment::Range;
use rs_merkle::{algorithms, MerkleProof};

use super::{Curve, LabelSeed};
use crate::{
    commitment::{Commitment, CommitmentOpening, CommitmentType, Direction},
    error::Error,
    tls_doc::TLSDoc,
};
use std::collections::HashMap;

/// The actual document which the Verifier will receive
pub struct VerifierDoc {
    version: u8,
    pub tls_doc: TLSDoc,
    /// Notary's signature over the [Signed] portion of this doc
    pub signature: Option<Signature>,

    // GC wire labels seed for the request data and the response data
    // These are the seeds from which IWLs are generated in
    // https://docs.tlsnotary.org/protocol/notarization/public_data_commitment.html
    pub labelSeed: LabelSeed,

    // The root of the Merkle tree of commitments. The User must prove that each [Commitment] is in the
    // Merkle tree.
    // This approach allows the User to hide from the Notary the exact amount of commitments thus
    // increasing User privacy against the Notary.
    // The root was made known to the Notary before the Notary opened his garbled circuits
    // to the User
    pub merkle_root: [u8; 32],

    // The total leaf count in the Merkle tree of commitments. Provided by the User to the Verifier
    // to enable merkle proof verification.
    pub merkle_tree_leaf_count: usize,

    // A proof that all [commitments] are the leaves of the Merkle tree
    pub merkle_multi_proof: MerkleProof<algorithms::Sha256>,

    // User's commitments to various portions of the TLS transcripts, sorted ascendingly by id
    commitments: Vec<Commitment>,

    // Openings for the commitments, sorted ascendingly by id
    commitment_openings: Vec<CommitmentOpening>,
}

impl VerifierDoc {
    // pub fn new() -> Self {
    //     //todo
    // }

    /// Performs sanity checks on the VerifierDoc:
    // - at least one commitment is present
    // - commitments and openings have their ids incremental and ascending
    // - commitment count equals opening count
    // - ranges inside one commitment are non-empty, valid, ascending, non-overlapping, non-overflowing
    // - the length of each opening equals the amount of committed data in ranges
    // - the total amount of committed data is less than 1GB to prevent DoS:
    //   (this will cause the verifier to hash up to a max of 1GB * 128 = 128GB of labels)
    // - the amount of commitments is less that 1000 (searching for overlapping commitments in a naive
    //   way has quadratic cost, hence this number shouldn't be too high to prevent DoS)
    // - overlapping openings must match exactly
    // - each [merkle_tree_index] is both unique and also ascending between commitments

    pub fn check(&self) -> Result<(), Error> {
        // - at least one commitment is present
        if self.commitments.is_empty() {
            return Err(Error::SanityCheckError);
        }

        // - commitments and openings have their ids incremental and ascending
        for i in 0..self.commitments.len() {
            if !(self.commitments[i].id == i && self.commitment_openings[i].id == i) {
                return Err(Error::SanityCheckError);
            }
        }

        // - commitment count equals opening count
        if self.commitments.len() != self.commitment_openings.len() {
            return Err(Error::SanityCheckError);
        }

        // - ranges inside one commitment are non-empty, valid, ascending, non-overlapping, non-overflowing,
        for c in &self.commitments {
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

        // - the length of each opening equals the amount of committed data in ranges
        // - the total amount of committed data is less than 1GB to prevent DoS
        let mut total_committed = 0usize;

        for i in 0..self.commitment_openings.len() {
            let expected = self.commitment_openings[i].opening.len();
            let mut total_in_ranges = 0usize;
            for r in &self.commitments[i].ranges {
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

        // - the amount of commitments is less that 1000
        if self.commitments.len() >= 1000 {
            return Err(Error::SanityCheckError);
        }

        // - overlapping openings must match exactly
        self.check_overlapping_openings()?;

        // - each [merkle_tree_index] is both unique and also ascending between commitments
        let indices: Vec<usize> = self
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
    fn check_overlapping_openings(&self) -> Result<(), Error> {
        // Note: using an existing lib to find multi-range overlap would incur the need to audit
        // that lib for correctness. Instead, since checking two range overlap is cheap, we are using
        // a naive way where we compare each range to all other ranges.
        // This naive way will have redundancy in computation but it will be easy to audit.

        for needle_c in self.commitments.iter() {
            // Naming convention: we use the prefix "needle" to indicate the range that we are
            // looking for (and to indicate the associates offsets, commitments and openings).
            // Likewise the prefix "haystack" indicates _where_ we are searching.

            // byte offset in the opening
            let mut needle_offset = 0usize;

            for needle_range in &needle_c.ranges {
                for haystack_c in self.commitments.iter() {
                    if needle_c.id == haystack_c.id {
                        // don't search within the same commitment
                        continue;
                    }

                    // byte offset in the opening
                    let mut haystack_offset = 0usize;
                    // will be set to true when overlap is found
                    let mut overlap_was_found = false;

                    for haystack_range in &haystack_c.ranges {
                        match self.overlapping_range(needle_range, haystack_range) {
                            Some(ov_range) => {
                                // the bytesize of the overlap
                                let overlap_size = ov_range.end - ov_range.start;

                                // Find offsets (in the openings) from which the overlap starts
                                let needle_ov_start =
                                    needle_offset + (ov_range.start - needle_range.start);
                                let haystack_ov_start =
                                    haystack_offset + (ov_range.start - haystack_range.start);

                                // get the openings which overlapped
                                // TODO: will later add a method get_opening_by_id()
                                let needle_o = &self.commitment_openings[needle_c.id];
                                let haystack_o = &self.commitment_openings[haystack_c.id];

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
    fn overlapping_range(&self, a: &Range, b: &Range) -> Option<Range> {
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

    /// verifies the data
    pub fn verify(&self, dns_name: String) -> Result<(), Error> {
        // verify the TLS portion of the doc
        self.tls_doc.verify(dns_name)?;

        self.verify_merkle_proofs()?;

        self.verify_commitments()?;

        Ok(())
    }

    // Verify that each commitment is present in the Merkle tree
    fn verify_merkle_proofs(&self) -> Result<(), Error> {
        // collect all merkle tree leaf indices and corresponding hashes
        // we already checked earlier that indices are unique and ascending
        let (leaf_indices, leaf_hashes): (Vec<usize>, Vec<[u8; 32]>) = self
            .commitments
            .iter()
            .map(|c| (c.merkle_tree_index, c.commitment))
            .unzip();

        if !self.merkle_multi_proof.verify(
            self.merkle_root,
            &leaf_indices,
            &leaf_hashes,
            self.merkle_tree_leaf_count,
        ) {
            return Err(Error::MerkleProofVerificationFailed);
        }

        Ok(())
    }

    fn verify_commitments(&self) -> Result<(), Error> {
        self.verify_label_commitments()?;

        // verify any other types of commitments here

        Ok(())
    }

    // Verify each label commitment against its opening
    fn verify_label_commitments(&self) -> Result<(), Error> {
        // collect only label commitments
        let label_commitments: Vec<&Commitment> = self
            .commitments
            .iter()
            .filter(|c| c.typ == CommitmentType::labels_blake3)
            .collect();

        // map each opening to its id
        let mut openings_ids: HashMap<usize, &CommitmentOpening> = HashMap::new();
        for o in &self.commitment_openings {
            openings_ids.insert(o.id, o);
        }

        // collect only openings corresponding to label commitments
        let mut openings: Vec<&CommitmentOpening> = Vec::with_capacity(label_commitments.len());
        for c in &label_commitments {
            match openings_ids.get(&c.id) {
                Some(opening) => openings.push(opening),
                // should never happen since we already checked that each opening has a
                // corresponding commitment in [VerifierDoc::check()]
                _ => return Err(Error::InternalError),
            }
        }

        // verify each (commitment, opening) pair
        for (o, c) in openings.iter().zip(label_commitments) {
            c.verify(o, &self.labelSeed)?;
        }

        Ok(())
    }
}

#[derive(Clone)]
struct Pubkey {
    typ: Curve,
    pubkey: Vec<u8>,
}

// signature for the notarization doc
#[derive(Clone)]
pub struct Signature {
    pub typ: Curve,
    pub signature: Vec<u8>,
}

#[test]
// test that jumping to an arbitrary stream offset works as expected
fn test_chacha() {
    use rand::Rng;
    use rand_chacha::ChaCha12Rng;
    use rand_core::SeedableRng;

    let mut rng = ChaCha12Rng::from_seed([0u8; 32]);
    let v1: u128 = rng.gen();
    let v2: u128 = rng.gen();

    let mut rng2 = ChaCha12Rng::from_seed([0u8; 32]);
    // jump to 128 bit offset
    rng2.set_word_pos(4);
    let w1: u128 = rng2.gen();

    assert_eq!(v2, w1);
}
