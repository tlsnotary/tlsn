use super::checks;
use crate::{
    commitment::{Commitment, CommitmentOpening},
    error::Error,
    merkle::MerkleProof,
    tls_handshake::TLSHandshake,
    LabelSeed,
};
use serde::Serialize;

/// Notarization document in its unchecked form. This is the form in which the document is received
/// by the Verifier from the User.
#[derive(Serialize, Clone)]
pub struct UncheckedDoc {
    /// All fields are exactly as in [VerifiedDoc]
    version: u8,
    tls_handshake: TLSHandshake,
    signature: Option<Vec<u8>>,
    label_seed: LabelSeed,
    merkle_root: [u8; 32],
    merkle_tree_leaf_count: u32,
    merkle_multi_proof: MerkleProof,
    commitments: Vec<Commitment>,
    commitment_openings: Vec<CommitmentOpening>,
}

impl UncheckedDoc {
    /// Creates a new unchecked document. This method is called only by the User.
    pub fn new(
        version: u8,
        tls_handshake: TLSHandshake,
        signature: Option<Vec<u8>>,
        label_seed: LabelSeed,
        merkle_root: [u8; 32],
        merkle_tree_leaf_count: u32,
        merkle_multi_proof: MerkleProof,
        commitments: Vec<Commitment>,
        commitment_openings: Vec<CommitmentOpening>,
    ) -> Self {
        Self {
            version,
            tls_handshake,
            signature,
            label_seed,
            merkle_root,
            merkle_tree_leaf_count,
            merkle_multi_proof,
            commitments,
            commitment_openings,
        }
    }

    /// Validate the unchecked document
    pub fn validate(&self) -> Result<(), Error> {
        // Performs the following validation checks:
        //
        // - at least one commitment is present
        checks::check_at_least_one_commitment_present(self)?;

        // - commitment count equals opening count
        checks::check_commitment_and_opening_count_equal(self)?;

        // - each [commitment, opening] pair has their id incremental and ascending. The types of commitment
        //   and opening match.
        checks::check_commitment_and_opening_pairs(self)?;

        // - ranges inside one commitment are non-empty, valid, ascending, non-overlapping, non-overflowing
        checks::check_ranges_inside_each_commitment(self)?;

        // - the total amount of committed data is not more than [super::MAX_TOTAL_COMMITTED_DATA]
        checks::check_max_total_committed_data(self)?;

        // - the length of each opening equals the amount of committed data in the ranges of the
        //   corresponding commitment
        checks::check_commitment_sizes(self)?;

        // - the amount of commitments is not more than [super::MAX_COMMITMENT_COUNT]
        checks::check_commitment_count(self)?;

        // - overlapping openings must match exactly
        checks::check_overlapping_openings(self)?;

        // - each [merkle_tree_index] is both unique and also ascending between commitments
        checks::check_merkle_tree_indices(self)?;

        // - openings of LabelsBlake3 type must have their label seed match the label seed which the
        //   Notary signed
        checks::check_labels_opening(self)?;

        Ok(())
    }

    pub fn version(&self) -> u8 {
        self.version
    }

    pub fn tls_handshake(&self) -> &TLSHandshake {
        &self.tls_handshake
    }

    pub fn signature(&self) -> &Option<Vec<u8>> {
        &self.signature
    }

    pub fn label_seed(&self) -> &LabelSeed {
        &self.label_seed
    }

    pub fn merkle_root(&self) -> &[u8; 32] {
        &self.merkle_root
    }

    pub fn merkle_tree_leaf_count(&self) -> u32 {
        self.merkle_tree_leaf_count
    }

    pub fn merkle_multi_proof(&self) -> &MerkleProof {
        &self.merkle_multi_proof
    }

    pub fn commitments(&self) -> &Vec<Commitment> {
        &self.commitments
    }

    pub fn commitment_openings(&self) -> &Vec<CommitmentOpening> {
        &self.commitment_openings
    }

    #[cfg(test)]
    pub fn set_commitments(&mut self, commitments: Vec<Commitment>) {
        self.commitments = commitments;
    }

    #[cfg(test)]
    pub fn set_commitment_openings(&mut self, commitment_openings: Vec<CommitmentOpening>) {
        self.commitment_openings = commitment_openings;
    }

    #[cfg(test)]
    pub fn set_signature(&mut self, signature: Option<Vec<u8>>) {
        self.signature = signature;
    }

    #[cfg(test)]
    pub fn set_merkle_root(&mut self, merkle_root: [u8; 32]) {
        self.merkle_root = merkle_root;
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::{
        commitment::{SomeFutureVariantOpening, TranscriptRange},
        doc::{unchecked::UncheckedDoc, MAX_COMMITMENT_COUNT, MAX_TOTAL_COMMITTED_DATA},
        test::{default_unchecked_doc, unchecked_doc},
        Signed,
    };
    use rstest::{fixture, rstest};

    #[fixture]
    // Returns an unchecked document which passes validation and the document's signed portion
    pub fn unchecked_doc_valid_and_signed() -> (UncheckedDoc, Signed) {
        let (doc, _, signed) = default_unchecked_doc();
        (doc, signed)
    }

    #[fixture]
    // Returns an unchecked document which passes validation
    pub fn unchecked_doc_valid() -> UncheckedDoc {
        let (doc, _) = unchecked_doc_valid_and_signed();
        doc
    }

    #[fixture]
    // Returns a set of valid documents which pass validation. Each document contains overlapping
    // commitments. Each document's commitments overlap in a unique way.
    fn unchecked_docs_valid_overlap() -> Vec<UncheckedDoc> {
        let mut docs = Vec::new();

        // overlap on the left of one of the ranges of comm2
        let comm1_ranges = vec![
            TranscriptRange::new(5, 15).unwrap(),
            TranscriptRange::new(20, 22).unwrap(),
        ];
        let comm2_ranges = vec![
            TranscriptRange::new(14, 18).unwrap(),
            TranscriptRange::new(23, 24).unwrap(),
        ];
        docs.push(unchecked_doc(vec![comm1_ranges, comm2_ranges]).0);

        // overlap on the right of one of the ranges of comm2
        let comm1_ranges = vec![
            TranscriptRange::new(5, 15).unwrap(),
            TranscriptRange::new(20, 22).unwrap(),
        ];
        let comm2_ranges = vec![
            TranscriptRange::new(0, 8).unwrap(),
            TranscriptRange::new(23, 24).unwrap(),
        ];
        docs.push(unchecked_doc(vec![comm1_ranges, comm2_ranges]).0);

        // one of the ranges of comm2 is fully enveloped by one of the range of comm1
        let comm1_ranges = vec![
            TranscriptRange::new(5, 15).unwrap(),
            TranscriptRange::new(20, 22).unwrap(),
        ];
        let comm2_ranges = vec![
            TranscriptRange::new(6, 10).unwrap(),
            TranscriptRange::new(23, 24).unwrap(),
        ];
        docs.push(unchecked_doc(vec![comm1_ranges, comm2_ranges]).0);

        // one of the ranges of comm2 is fully enveloped by one of the range of comm1
        // and the ranges' start bounds match
        let comm1_ranges = vec![
            TranscriptRange::new(5, 15).unwrap(),
            TranscriptRange::new(20, 22).unwrap(),
        ];
        let comm2_ranges = vec![
            TranscriptRange::new(5, 10).unwrap(),
            TranscriptRange::new(23, 24).unwrap(),
        ];
        docs.push(unchecked_doc(vec![comm1_ranges, comm2_ranges]).0);

        // one of the ranges of comm2 is fully enveloped by one of the range of comm1
        // and the ranges' end bounds match
        let comm1_ranges = vec![
            TranscriptRange::new(5, 15).unwrap(),
            TranscriptRange::new(20, 22).unwrap(),
        ];
        let comm2_ranges = vec![
            TranscriptRange::new(6, 15).unwrap(),
            TranscriptRange::new(23, 24).unwrap(),
        ];
        docs.push(unchecked_doc(vec![comm1_ranges, comm2_ranges]).0);

        // one of the ranges of comm2 fully envelops one of the range of comm1
        let comm1_ranges = vec![
            TranscriptRange::new(5, 15).unwrap(),
            TranscriptRange::new(20, 22).unwrap(),
        ];
        let comm2_ranges = vec![
            TranscriptRange::new(3, 17).unwrap(),
            TranscriptRange::new(23, 24).unwrap(),
        ];
        docs.push(unchecked_doc(vec![comm1_ranges, comm2_ranges]).0);

        // one of the ranges of comm2 fully envelops one of the range of comm1
        // and the ranges' start bounds match
        let comm1_ranges = vec![
            TranscriptRange::new(5, 15).unwrap(),
            TranscriptRange::new(20, 22).unwrap(),
        ];
        let comm2_ranges = vec![
            TranscriptRange::new(5, 17).unwrap(),
            TranscriptRange::new(23, 24).unwrap(),
        ];
        docs.push(unchecked_doc(vec![comm1_ranges, comm2_ranges]).0);

        // one of the ranges of comm2 fully envelops one of the range of comm1
        // and the ranges' end bounds match
        let comm1_ranges = vec![
            TranscriptRange::new(5, 15).unwrap(),
            TranscriptRange::new(20, 22).unwrap(),
        ];
        let comm2_ranges = vec![
            TranscriptRange::new(3, 15).unwrap(),
            TranscriptRange::new(23, 24).unwrap(),
        ];
        docs.push(unchecked_doc(vec![comm1_ranges, comm2_ranges]).0);

        // a range from comm1 matches exactly a range from comm2
        let comm1_ranges = vec![
            TranscriptRange::new(5, 15).unwrap(),
            TranscriptRange::new(20, 22).unwrap(),
        ];
        let comm2_ranges = vec![
            TranscriptRange::new(5, 15).unwrap(),
            TranscriptRange::new(23, 24).unwrap(),
        ];
        docs.push(unchecked_doc(vec![comm1_ranges, comm2_ranges]).0);

        docs
    }

    #[rstest]
    // Expect validation to succeed for a document with non-overlapping commitments
    fn validate_success_non_overlapping(unchecked_doc_valid: UncheckedDoc) {
        assert!(unchecked_doc_valid.validate().is_ok())
    }

    #[rstest]
    // Expect validation to succeed when document has overlapping commitments
    fn validate_success_overlapping(unchecked_docs_valid_overlap: Vec<UncheckedDoc>) {
        for doc in unchecked_docs_valid_overlap {
            assert!(doc.validate().is_ok())
        }
    }

    #[rstest]
    // Expect validation to fail on check_at_least_one_commitment_present()
    fn validate_fail_on_check_at_least_one_commitment_present(
        mut unchecked_doc_valid: UncheckedDoc,
    ) {
        // insert empty commitments vec
        unchecked_doc_valid.set_commitments(Vec::new());
        assert!(
            unchecked_doc_valid.validate().err().unwrap()
                == Error::ValidationCheckError("check_at_least_one_commitment_present".to_string())
        );
    }

    #[rstest]
    // Expect validation to fail on check_commitment_and_opening_count_equal()
    fn validate_fail_on_check_commitment_and_opening_count_equalt(
        mut unchecked_doc_valid: UncheckedDoc,
    ) {
        // append an extra commitment
        let mut original_comms = unchecked_doc_valid.commitments().to_vec();
        original_comms.push(Commitment::default());

        unchecked_doc_valid.set_commitments(original_comms);
        assert!(
            unchecked_doc_valid.validate().err().unwrap()
                == Error::ValidationCheckError(
                    "check_commitment_and_opening_count_equal".to_string()
                )
        );
    }

    #[rstest]
    // Expect validation to fail on check_commitment_and_opening_count_equal()
    fn validate_fail_on_check_commitment_and_opening_count_equal(
        mut unchecked_doc_valid: UncheckedDoc,
    ) {
        // append an extra commitment
        let mut original_comms = unchecked_doc_valid.commitments().to_vec();
        original_comms.push(Commitment::default());

        unchecked_doc_valid.set_commitments(original_comms);
        assert!(
            unchecked_doc_valid.validate().err().unwrap()
                == Error::ValidationCheckError(
                    "check_commitment_and_opening_count_equal".to_string()
                )
        );
    }

    #[rstest]
    // Expect validation to fail on check_commitment_and_opening_pairs()
    fn validate_fail_on_check_commitment_and_opening_pairs(unchecked_doc_valid: UncheckedDoc) {
        // ------------------- Change ids so that they don't start from 0 anymore. Keep them in
        //                     incrementing order.

        let mut doc1 = unchecked_doc_valid.clone();

        // change commitment ids
        let mut new_commitments = doc1.commitments().to_vec();
        new_commitments[0].set_id(1);
        new_commitments[1].set_id(2);
        doc1.set_commitments(new_commitments);

        // change opening ids
        let original_openings = doc1.commitment_openings().to_vec();
        let new_openings = original_openings
            .iter()
            .enumerate()
            .map(|(idx, opening)| match opening {
                CommitmentOpening::LabelsBlake3(ref opening) => {
                    let mut new_opening = opening.clone();
                    new_opening.set_id(idx as u32 + 1);
                    CommitmentOpening::LabelsBlake3(new_opening)
                }
                CommitmentOpening::SomeFutureVariant(ref opening) => {
                    let mut new_opening = opening.clone();
                    new_opening.set_id(idx as u32 + 1);
                    CommitmentOpening::SomeFutureVariant(new_opening)
                }
            })
            .collect();
        doc1.set_commitment_openings(new_openings);

        assert!(
            doc1.validate().err().unwrap()
                == Error::ValidationCheckError("check_commitment_and_opening_pairs".to_string())
        );

        // ---------------Modify ids to not be incremental

        let mut doc2 = unchecked_doc_valid.clone();

        // change 2nd commitment id
        let mut commitments = doc2.commitments().to_vec();
        commitments[1].set_id(2);
        doc2.set_commitments(commitments);

        // change 2nd opening id
        let original_openings = doc2.commitment_openings().to_vec();
        let new_opening = match original_openings[1] {
            CommitmentOpening::SomeFutureVariant(ref opening) => {
                let mut new_opening = opening.clone();
                new_opening.set_id(2);
                CommitmentOpening::SomeFutureVariant(new_opening)
            }
            _ => panic!(),
        };

        doc2.set_commitment_openings(vec![original_openings[0].clone(), new_opening]);

        assert!(
            doc2.validate().err().unwrap()
                == Error::ValidationCheckError("check_commitment_and_opening_pairs".to_string())
        );

        // --------------- Modify commitment id so that commitment-opening pair ids don't match

        let mut doc3 = unchecked_doc_valid.clone();
        // change 2nd commitment id
        let mut commitments = doc3.commitments().to_vec();
        commitments[1].set_id(2);
        doc3.set_commitments(commitments);

        assert!(
            doc3.validate().err().unwrap()
                == Error::ValidationCheckError("check_commitment_and_opening_pairs".to_string())
        );

        // ---------------Modify opening type so that it doesn't match the commitment type

        let mut doc4 = unchecked_doc_valid;

        let original_openings = doc4.commitment_openings().to_vec();

        // change 1st opening type
        let new_opening = CommitmentOpening::SomeFutureVariant(SomeFutureVariantOpening::default());

        doc4.set_commitment_openings(vec![new_opening, original_openings[1].clone()]);

        assert!(
            doc4.validate().err().unwrap()
                == Error::ValidationCheckError("check_commitment_and_opening_pairs".to_string())
        );
    }

    #[rstest]
    // Expect validation to fail on check_ranges_inside_each_commitment()
    fn validate_fail_on_check_ranges_inside_each_commitment(unchecked_doc_valid: UncheckedDoc) {
        //-------------- Change ranges to be empty
        let mut doc1 = unchecked_doc_valid.clone();

        let mut new_commitments = doc1.commitments().to_vec();
        new_commitments[0].set_ranges(Vec::new());

        doc1.set_commitments(new_commitments);
        assert!(
            doc1.validate().err().unwrap()
                == Error::ValidationCheckError("check_ranges_inside_each_commitment".to_string())
        );

        //-------------- Change range to be invalid
        let mut doc2 = unchecked_doc_valid.clone();

        let mut new_commitments = doc2.commitments().to_vec();
        let mut new_ranges = new_commitments[0].ranges().clone();

        new_ranges[0] = TranscriptRange::new_unchecked(5, 5);
        new_commitments[0].set_ranges(new_ranges);

        doc2.set_commitments(new_commitments);
        assert!(
            doc2.validate().err().unwrap()
                == Error::ValidationCheckError("check_ranges_inside_each_commitment".to_string())
        );

        //-------------- Change ranges to overlap
        let mut doc3 = unchecked_doc_valid.clone();

        let mut new_commitments = doc3.commitments().to_vec();

        new_ranges = vec![
            TranscriptRange::new(5, 19).unwrap(),
            TranscriptRange::new(18, 22).unwrap(),
        ];
        new_commitments[0].set_ranges(new_ranges);

        doc3.set_commitments(new_commitments);
        assert!(
            doc3.validate().err().unwrap()
                == Error::ValidationCheckError("check_ranges_inside_each_commitment".to_string())
        );

        //-------------- Change ranges to not be ascending relative to each other
        let mut doc4 = unchecked_doc_valid;

        let mut new_commitments = doc4.commitments().to_vec();

        new_ranges = vec![
            TranscriptRange::new(20, 22).unwrap(),
            TranscriptRange::new(5, 19).unwrap(),
        ];
        new_commitments[0].set_ranges(new_ranges);

        doc4.set_commitments(new_commitments);
        assert!(
            doc4.validate().err().unwrap()
                == Error::ValidationCheckError("check_ranges_inside_each_commitment".to_string())
        );
    }

    #[rstest]
    // Expect validation to fail on check_max_total_committed_data()
    fn validate_fail_on_check_max_total_committed_data(unchecked_doc_valid: UncheckedDoc) {
        //-------------- Change total committed data to be > super::MAX_TOTAL_COMMITMENT_SIZE
        let mut doc1 = unchecked_doc_valid;

        let mut new_commitments = doc1.commitments().to_vec();
        let new_ranges = vec![
            TranscriptRange::new(0, MAX_TOTAL_COMMITTED_DATA as u32).unwrap(),
            TranscriptRange::new(
                MAX_TOTAL_COMMITTED_DATA as u32,
                MAX_TOTAL_COMMITTED_DATA as u32 + 1,
            )
            .unwrap(),
        ];

        new_commitments[0].set_ranges(new_ranges);

        doc1.set_commitments(new_commitments);
        assert!(
            doc1.validate().err().unwrap()
                == Error::ValidationCheckError("check_max_total_committed_data".to_string())
        );
    }

    #[rstest]
    // Expect validation to fail on check_commitment_sizes()
    fn validate_fail_on_check_commitment_sizes(unchecked_doc_valid: UncheckedDoc) {
        //-------------- Change commitment range sizes to not correspond to the opening size

        let mut doc1 = unchecked_doc_valid;

        let mut new_commitments = doc1.commitments().to_vec();
        let mut new_ranges = new_commitments[0].ranges().clone();
        new_ranges[0] =
            TranscriptRange::new(new_ranges[0].start(), new_ranges[0].end() + 1).unwrap();

        new_commitments[0].set_ranges(new_ranges);

        doc1.set_commitments(new_commitments);
        assert!(
            doc1.validate().err().unwrap()
                == Error::ValidationCheckError("check_commitment_sizes".to_string())
        );
    }

    #[rstest]
    // Expect validation to fail on check_commitment_count()
    fn validate_fail_on_check_commitment_count(unchecked_doc_valid: UncheckedDoc) {
        //-------------- Change commitment count to be too high

        let mut doc1 = unchecked_doc_valid;

        let original_commitments = doc1.commitments().to_vec();

        let new_commitments: Vec<Commitment> = (0..MAX_COMMITMENT_COUNT + 1)
            .map(|i| {
                let mut new = original_commitments[0].clone();
                // set correct id
                new.set_id(i as u32);
                new
            })
            .collect();

        // the amount of openings must be adjusted to match the new amount of commitments
        let original_openings = doc1.commitment_openings().to_vec();

        let new_openings: Vec<CommitmentOpening> = (0..MAX_COMMITMENT_COUNT + 1)
            .map(|i| match original_openings[0] {
                CommitmentOpening::LabelsBlake3(ref opening) => {
                    let mut new_opening = opening.clone();
                    // set correct id
                    new_opening.set_id(i as u32);
                    CommitmentOpening::LabelsBlake3(new_opening)
                }
                _ => panic!(),
            })
            .collect();

        doc1.set_commitments(new_commitments);
        doc1.set_commitment_openings(new_openings);

        assert!(
            doc1.validate().err().unwrap()
                == Error::ValidationCheckError("check_commitment_count".to_string())
        );
    }

    #[rstest]
    // Expect validation to fail on check_overlapping_openings()
    fn validate_fail_on_check_overlapping_openings(
        unchecked_docs_valid_overlap: Vec<UncheckedDoc>,
    ) {
        for mut doc in unchecked_docs_valid_overlap {
            // modify openings such that the overlapping bytes will not match:
            // first opening's bytes are set to all 'a's
            // second opening's bytes are set to all 'b's

            let openings = doc.commitment_openings();
            let new_opening1 = match openings[0] {
                CommitmentOpening::LabelsBlake3(ref opening) => {
                    let mut new_opening = opening.clone();
                    // set new opening bytes
                    new_opening.set_opening(vec![b'a'; opening.opening().len()]);
                    CommitmentOpening::LabelsBlake3(new_opening)
                }
                _ => panic!(),
            };

            let new_opening2 = match openings[1] {
                CommitmentOpening::SomeFutureVariant(ref opening) => {
                    let mut new_opening = opening.clone();
                    // set new opening bytes
                    new_opening.set_opening(vec![b'b'; opening.opening().len()]);
                    CommitmentOpening::SomeFutureVariant(new_opening)
                }
                _ => panic!(),
            };

            doc.set_commitment_openings(vec![new_opening1, new_opening2]);
            assert!(doc.validate().err().unwrap() == Error::OverlappingOpeningsDontMatch);
        }
    }

    #[rstest]
    // Expect validation to fail on check_merkle_tree_indices()
    fn validate_fail_on_check_merkle_tree_indicess(unchecked_doc_valid: UncheckedDoc) {
        //-------------- Change merkle tree index on one commitment so that indices
        //               are not unique anymore

        let mut doc1 = unchecked_doc_valid.clone();

        let mut commitments = doc1.commitments().to_vec();

        let comm1_index = commitments[0].merkle_tree_index();
        commitments[1].set_merkle_tree_index(comm1_index);

        doc1.set_commitments(commitments);
        assert!(
            doc1.validate().err().unwrap()
                == Error::ValidationCheckError("check_merkle_tree_indices".to_string())
        );

        //-------------- Switch commitment indices around so that indices are not ascending anymore

        let mut doc2 = unchecked_doc_valid.clone();

        let mut commitments = doc2.commitments().to_vec();

        let comm1_index = commitments[0].merkle_tree_index();
        let comm2_index = commitments[1].merkle_tree_index();
        commitments[0].set_merkle_tree_index(comm2_index);
        commitments[1].set_merkle_tree_index(comm1_index);

        doc2.set_commitments(commitments);
        assert!(
            doc2.validate().err().unwrap()
                == Error::ValidationCheckError("check_merkle_tree_indices".to_string())
        );

        //-------------- Set index to be larger than the index of the last leaf in the tree
        let mut doc3 = unchecked_doc_valid;

        let mut commitments = doc3.commitments().to_vec();
        commitments[0].set_merkle_tree_index(doc3.merkle_tree_leaf_count());

        doc3.set_commitments(commitments);
        assert!(
            doc3.validate().err().unwrap()
                == Error::ValidationCheckError("check_merkle_tree_indices".to_string())
        );
    }

    #[rstest]
    // Expect validation to fail on check_labels_opening()
    fn validate_fail_on_check_labels_opening(unchecked_doc_valid: UncheckedDoc) {
        //-------------- Modify label_seed in the opening so that it doesn't match
        //              label_seed of the document

        let mut doc1 = unchecked_doc_valid;

        let openings = doc1.commitment_openings();

        let new_opening1 = match openings[0] {
            CommitmentOpening::LabelsBlake3(ref opening) => {
                let mut new_opening = opening.clone();
                let mut seed = *opening.label_seed();
                // modify the seed's byte
                seed[0] = seed[0].checked_add(1).unwrap_or(0);
                new_opening.set_label_seed(seed);
                CommitmentOpening::LabelsBlake3(new_opening)
            }
            _ => panic!(),
        };

        doc1.set_commitment_openings(vec![new_opening1, openings[1].clone()]);
        assert!(
            doc1.validate().err().unwrap()
                == Error::ValidationCheckError("check_labels_opening".to_string())
        );
    }
}
