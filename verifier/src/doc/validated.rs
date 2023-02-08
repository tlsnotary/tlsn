use crate::{
    commitment::{Commitment, CommitmentOpening, CommitmentType},
    doc::unchecked::UncheckedDoc,
    error::Error,
    merkle::MerkleProof,
    tls_handshake::TLSHandshake,
    LabelSeed, PubKey, Signed,
};
use serde::{ser::Serializer, Serialize};
use std::collections::HashMap;

/// Notarization document in its validated form (not yet verified)
pub(crate) struct ValidatedDoc {
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
            label_seed: unchecked.label_seed().clone(),
            merkle_root: unchecked.merkle_root().clone(),
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
    /// Note that we already checked in [checks::check_merkle_tree_indices] that indices are
    /// unique and ascending
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
        // collect only label commitments
        let label_commitments: Vec<&Commitment> = self
            .commitments
            .iter()
            .filter(|c| *c.typ() == CommitmentType::labels_blake3)
            .collect();

        // map each opening to its id
        let mut openings_ids: HashMap<usize, &CommitmentOpening> = HashMap::new();
        for o in &self.commitment_openings {
            let opening_id = match o {
                CommitmentOpening::LabelsBlake3(opening) => opening.id(),
                #[cfg(test)]
                CommitmentOpening::SomeFutureVariant(ref opening) => opening.id(),
            };
            openings_ids.insert(opening_id as usize, o);
        }

        // collect only openings corresponding to label commitments
        let mut openings: Vec<&CommitmentOpening> = Vec::with_capacity(label_commitments.len());
        for c in &label_commitments {
            match openings_ids.get(&(c.id() as usize)) {
                Some(opening) => openings.push(opening),
                // should never happen since we already checked that each opening has a
                // corresponding commitment in validate() of [crate::doc::unchecked::UncheckedDoc]
                _ => return Err(Error::InternalError),
            }
        }

        // verify each (opening, commitment) pair
        for (o, c) in openings.iter().zip(label_commitments) {
            c.verify(o)?;
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
}
