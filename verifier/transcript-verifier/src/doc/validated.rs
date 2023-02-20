use crate::{
    commitment::Commitment, doc::unchecked::UncheckedDoc, error::Error, tls_handshake::TLSHandshake,
};
use std::collections::HashMap;
use transcript_core::{
    commitment::{CommitmentOpening, CommitmentType},
    merkle::MerkleProof,
    signed::Signed,
    LabelSeed,
};

/// Notarization document in its validated form (not yet verified)
pub(crate) struct ValidatedDoc {
    /// All fields are exactly as in [crate::doc::verified::VerifiedDoc]
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

impl ValidatedDoc {
    /// Returns a new [ValidatedDoc] after performing all validation checks
    pub(crate) fn from_unchecked(unchecked: UncheckedDoc) -> Result<Self, Error> {
        unchecked.validate()?;

        // Make sure the Notary's signature is present.
        // (If the Verifier IS also the Notary then the signature is NOT needed. `ValidatedDoc`
        // should be created with `from_unchecked_with_signed_data()` instead.)

        if unchecked.signature().is_none() {
            return Err(Error::SignatureExpected);
        }

        Ok(Self {
            version: unchecked.version(),
            tls_handshake: unchecked.tls_handshake().clone(),
            signature: unchecked.signature().clone(),
            label_seed: *unchecked.label_seed(),
            merkle_root: *unchecked.merkle_root(),
            merkle_tree_leaf_count: unchecked.merkle_tree_leaf_count(),
            merkle_multi_proof: unchecked.merkle_multi_proof().clone(),
            commitments: unchecked.commitments().clone(),
            commitment_openings: unchecked.commitment_openings().clone(),
        })
    }

    /// Returns a new [ValidatedDoc] after performing all validation checks and adding the signed data.
    /// `signed_data` (despite its name) is not actually signed because it was created locally by
    /// the calling Verifier who had acted as the Notary during notarization.
    pub(crate) fn from_unchecked_with_signed_data(
        unchecked: UncheckedDoc,
        signed_data: Signed,
    ) -> Result<Self, Error> {
        unchecked.validate()?;

        // Make sure the Notary's signature is NOT present.
        // (If the Verifier is NOT the Notary then the Notary's signature IS needed. `ValidatedDoc`
        // should be created with `from_unchecked()` instead.)

        if unchecked.signature().is_some() {
            return Err(Error::SignatureNotExpected);
        }

        // insert `signed_data` which we had created locally

        let tls_handshake = TLSHandshake::new(
            signed_data.tls().clone(),
            unchecked.tls_handshake().handshake_data().clone(),
        );
        let label_seed = *signed_data.label_seed();
        let merkle_root = *signed_data.merkle_root();

        Ok(Self {
            version: unchecked.version(),
            tls_handshake,
            signature: unchecked.signature().clone(),
            label_seed,
            merkle_root,
            merkle_tree_leaf_count: unchecked.merkle_tree_leaf_count(),
            merkle_multi_proof: unchecked.merkle_multi_proof().clone(),
            commitments: unchecked.commitments().clone(),
            commitment_openings: unchecked.commitment_openings().clone(),
        })
    }

    /// Verifies the document. This includes verifying:
    /// - the TLS document
    /// - the inclusion of commitments in the Merkle tree
    /// - each commitment
    pub(crate) fn verify(&self, dns_name: &str) -> Result<(), Error> {
        self.tls_handshake.verify(dns_name)?;

        self.verify_merkle_proofs()?;

        self.verify_commitments()?;

        Ok(())
    }

    /// Verifies that each commitment is present in the Merkle tree.
    ///
    /// Note that we already checked in [crate::doc::checks::check_merkle_tree_indices] that indices
    /// are unique and ascending
    fn verify_merkle_proofs(&self) -> Result<(), Error> {
        // collect all merkle tree leaf indices and corresponding hashes
        let (leaf_indices, leaf_hashes): (Vec<usize>, Vec<[u8; 32]>) = self
            .commitments
            .iter()
            .map(|c| (c.merkle_tree_index() as usize, c.commitment()))
            .unzip();

        // verify the inclusion of multiple leaves
        if !self.merkle_multi_proof.0.verify(
            self.merkle_root,
            &leaf_indices,
            &leaf_hashes,
            self.merkle_tree_leaf_count as usize,
        ) {
            return Err(Error::MerkleProofVerificationFailed);
        }

        Ok(())
    }

    /// Verifies commitments to notarized data
    fn verify_commitments(&self) -> Result<(), Error> {
        self.verify_label_commitments()?;

        // verify any other types of commitments here

        Ok(())
    }

    /// Verifies each garbled circuit label commitment against its opening
    fn verify_label_commitments(&self) -> Result<(), Error> {
        // map each opening to its id
        let mut openings_ids: HashMap<usize, &CommitmentOpening> = HashMap::new();
        for o in &self.commitment_openings {
            let opening_id = match o {
                CommitmentOpening::LabelsBlake3(opening) => opening.id(),
            };
            openings_ids.insert(opening_id as usize, o);
        }

        for commitment in &self.commitments {
            // we only need label commitments
            if commitment.typ() == &CommitmentType::labels_blake3 {
                // get a corresponding opening
                let opening = match openings_ids.get(&(commitment.id() as usize)) {
                    Some(opening) => opening,
                    // should never happen since we already checked that each opening has a
                    // corresponding commitment in validate() of [crate::doc::unchecked::UncheckedDoc]
                    _ => return Err(Error::InternalError),
                };
                // verify
                commitment.verify(opening)?;
            }
        }

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
    pub fn set_merkle_tree_leaf_count(&mut self, merkle_tree_leaf_count: u32) {
        self.merkle_tree_leaf_count = merkle_tree_leaf_count;
    }

    #[cfg(test)]
    pub fn set_merkle_root(&mut self, merkle_root: [u8; 32]) {
        self.merkle_root = merkle_root;
    }

    #[cfg(test)]
    pub fn set_merkle_multi_proof(&mut self, merkle_multi_proof: MerkleProof) {
        self.merkle_multi_proof = merkle_multi_proof;
    }

    #[cfg(test)]
    pub fn set_signature(&mut self, signature: Option<Vec<u8>>) {
        self.signature = signature;
    }
}

/// Extracts relevant fields from [ValidatedDoc]. Those are the fields
/// which the Notary signs.
impl std::convert::From<&ValidatedDoc> for Signed {
    fn from(doc: &ValidatedDoc) -> Self {
        Signed::new(
            doc.tls_handshake().signed_handshake().clone(),
            *doc.label_seed(),
            *doc.merkle_root(),
        )
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::{
        doc::unchecked::test::{unchecked_doc_valid, unchecked_doc_valid_and_signed},
        test::default_unchecked_doc,
    };
    use rstest::{fixture, rstest};

    #[fixture]
    // Returns a validated document
    pub(crate) fn validated_doc() -> ValidatedDoc {
        validated_doc_and_signed().0
    }

    #[fixture]
    // Returns a validated document and its signed portion
    fn validated_doc_and_signed() -> (ValidatedDoc, Signed) {
        let (unchecked_doc, _, signed) = default_unchecked_doc();

        (ValidatedDoc::from_unchecked(unchecked_doc).unwrap(), signed)
    }

    #[rstest]
    // Expect from_unchecked() to fail since no signature is present
    fn test_from_unchecked_fail_no_sig() {
        let mut unchecked_doc = unchecked_doc_valid();
        unchecked_doc.set_signature(None);

        assert!(
            ValidatedDoc::from_unchecked(unchecked_doc).err().unwrap() == Error::SignatureExpected
        );
    }

    #[rstest]
    // Expect from_unchecked_with_signed_data() to succeed
    fn test_from_unchecked_with_signed_data_success() {
        let (mut unchecked_doc, signed) = unchecked_doc_valid_and_signed();
        // remove signature, it is not expected to be present
        unchecked_doc.set_signature(None);

        // corrupt some part of the doc which was signed, e.g. merkle_root
        let mut merkle_root = *unchecked_doc.merkle_root();
        merkle_root[0] = merkle_root[0].checked_add(1).unwrap_or(0);
        unchecked_doc.set_merkle_root(merkle_root);

        // the signed portion will replace the corrupted portion and the document will be verified
        // successfully
        assert!(ValidatedDoc::from_unchecked_with_signed_data(unchecked_doc, signed).is_ok());
    }

    #[rstest]
    // Expect from_unchecked_with_signed_data() to fail because a signature is present in the
    // document
    fn test_from_unchecked_with_signed_fail_sig_present() {
        // by default `unchecked_doc` has a signature
        let (unchecked_doc, signed) = unchecked_doc_valid_and_signed();
        assert!(
            ValidatedDoc::from_unchecked_with_signed_data(unchecked_doc, signed)
                .err()
                .unwrap()
                == Error::SignatureNotExpected
        );
    }

    #[rstest]
    // Expect verify_merkle_proofs() to succeed
    fn verify_merkle_proofs_success(validated_doc: ValidatedDoc) {
        assert!(validated_doc.verify_merkle_proofs().is_ok())
    }

    #[rstest]
    // Expect verify_merkle_proofs() to fail since one of the commitment's merkle tree index is wrong
    fn verify_merkle_proofs_fail_wrong_index(mut validated_doc: ValidatedDoc) {
        let mut commitments = validated_doc.commitments().clone();
        let old = commitments[0].merkle_tree_index();
        commitments[0].set_merkle_tree_index(old + 1);
        validated_doc.set_commitments(commitments);

        assert!(
            validated_doc.verify_merkle_proofs().err().unwrap()
                == Error::MerkleProofVerificationFailed
        );
    }

    #[rstest]
    // Expect verify_merkle_proofs() to fail since correct hashes are swapped, i.e now the hashes
    // corresponding to indices are incorrect
    fn verify_merkle_proofs_fail_wrong_hash(mut validated_doc: ValidatedDoc) {
        let mut commitments = validated_doc.commitments().clone();
        let hash1 = commitments[0].commitment();
        let hash2 = commitments[1].commitment();
        commitments[0].set_commitment(hash2);
        commitments[1].set_commitment(hash1);
        validated_doc.set_commitments(commitments);

        assert!(
            validated_doc.verify_merkle_proofs().err().unwrap()
                == Error::MerkleProofVerificationFailed
        );
    }

    #[rstest]
    // Expect verify_merkle_proofs() to fail since an extra (correct) leaf was provided
    // which is not covered by the proof
    fn verify_merkle_proofs_fail_extra_leaf(mut validated_doc: ValidatedDoc) {
        let mut commitments = validated_doc.commitments().clone();

        let mut new_commitment = commitments[0].clone();
        new_commitment.set_merkle_tree_index(1);
        new_commitment.set_commitment(crate::test::DUMMY_HASH);
        // During validation the tree indices between commitments are checked to be ascending.
        // Since this test skipped the validation, we make sure now that indices are ascending.
        commitments.splice(1..1, [new_commitment]);

        validated_doc.set_commitments(commitments);

        assert!(
            validated_doc.verify_merkle_proofs().err().unwrap()
                == Error::MerkleProofVerificationFailed
        );
    }

    #[rstest]
    // Expect verify_merkle_proofs() to fail since a leaf which was covered by the proof
    // is missing
    fn verify_merkle_proofs_fail_missing_leaf(mut validated_doc: ValidatedDoc) {
        let mut commitments = validated_doc.commitments().clone();
        commitments.pop();

        validated_doc.set_commitments(commitments);

        assert!(
            validated_doc.verify_merkle_proofs().err().unwrap()
                == Error::MerkleProofVerificationFailed
        );
    }

    #[rstest]
    // Expect verify_merkle_proofs() to fail because of the wrong merkle root
    fn verify_merkle_proofs_fail_wrong_root(mut validated_doc: ValidatedDoc) {
        let mut old = *validated_doc.merkle_root();
        // corrupt one byte
        old[0] = old[0].checked_add(1).unwrap_or(0);
        validated_doc.set_merkle_root(old);

        assert!(
            validated_doc.verify_merkle_proofs().err().unwrap()
                == Error::MerkleProofVerificationFailed
        );
    }

    #[rstest]
    // Expect verify_merkle_proofs() to fail because of the wrong merkle proof
    fn verify_merkle_proofs_fail_wrong_proof(mut validated_doc: ValidatedDoc) {
        use rs_merkle::{algorithms, MerkleProof as MerkleProof_rs_merkle};

        let old_proof = validated_doc.merkle_multi_proof().clone();
        let mut bytes = old_proof.0.to_bytes();
        // corrupt one byte
        bytes[0] = bytes[0].checked_add(1).unwrap_or(0);

        validated_doc.set_merkle_multi_proof(MerkleProof(
            MerkleProof_rs_merkle::<algorithms::Sha256>::from_bytes(&bytes).unwrap(),
        ));

        assert!(
            validated_doc.verify_merkle_proofs().err().unwrap()
                == Error::MerkleProofVerificationFailed
        );
    }

    // Ignored for now due to a panic in rs_merkle
    // https://github.com/antouhou/rs-merkle/issues/20
    #[ignore = "waiting for a panic in rs_merkle to be fixed"]
    #[rstest]
    // Expect verify_merkle_proofs() to fail since a wrong count of leaves in the tree is
    // provided
    fn verify_merkle_proofs_fail_wrong_leaf_count(mut validated_doc: ValidatedDoc) {
        validated_doc.set_merkle_tree_leaf_count(validated_doc.merkle_tree_leaf_count() + 1);

        assert!(
            validated_doc.verify_merkle_proofs().err().unwrap()
                == Error::MerkleProofVerificationFailed
        );
    }
}
