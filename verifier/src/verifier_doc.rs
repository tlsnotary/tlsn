use super::LabelSeed;
use crate::{
    checks,
    commitment::{Commitment, CommitmentOpening, CommitmentType},
    error::Error,
    tls_doc::TLSDoc,
};
use rs_merkle::{algorithms, proof_serializers, MerkleProof};
use serde::ser::Serializer;
use std::collections::HashMap;

#[derive(serde::Serialize)]
/// The notarization document received from the User after all sanity checks passed
pub struct VerifierDoc {
    version: u8,
    pub tls_doc: TLSDoc,
    /// Notary's signature over the [Signed] portion of this doc
    pub signature: Option<Vec<u8>>,

    // GC wire labels seed for the request data and the response data
    // This is the seeds from which IWLs are generated in
    // https://docs.tlsnotary.org/protocol/notarization/public_data_commitment.html
    pub label_seed: LabelSeed,

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
    #[serde(serialize_with = "merkle_proof_serialize")]
    pub merkle_multi_proof: MerkleProof<algorithms::Sha256>,

    // User's commitments to various portions of the TLS transcripts, sorted ascendingly by id
    commitments: Vec<Commitment>,

    // Openings for the commitments, sorted ascendingly by id
    commitment_openings: Vec<CommitmentOpening>,
}

/// Serialize the [MerkleProof] type using its native `serialize` method
fn merkle_proof_serialize<S>(
    proof: &MerkleProof<algorithms::Sha256>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let bytes = proof.serialize::<proof_serializers::DirectHashesOrder>();
    serializer.serialize_bytes(&bytes)
}

impl VerifierDoc {
    /// Creates a new doc. This method is called by the User. When passing the created doc
    /// to the Verifier, the User must convert this doc into VerifierDocUnchecked
    pub fn new(
        version: u8,
        tls_doc: TLSDoc,
        signature: Option<Vec<u8>>,
        label_seed: LabelSeed,
        merkle_root: [u8; 32],
        merkle_tree_leaf_count: usize,
        merkle_multi_proof: MerkleProof<algorithms::Sha256>,
        commitments: Vec<Commitment>,
        commitment_openings: Vec<CommitmentOpening>,
    ) -> Self {
        Self {
            version,
            tls_doc,
            signature,
            label_seed,
            merkle_root,
            merkle_tree_leaf_count,
            merkle_multi_proof,
            commitments,
            commitment_openings,
        }
    }

    /// Returns a new VerifierDoc after performing all sanity checks. This is the only way
    /// for the Verifier to derive VerifierDoc
    pub fn from_unchecked(unchecked: VerifierDocUnchecked) -> Result<Self, Error> {
        // Performs the following sanity checks:
        //
        // - at least one commitment is present
        checks::check_at_least_one_commitment_present(&unchecked)?;

        // - commitments and openings have their ids incremental and ascending
        checks::check_commitment_and_opening_ids(&unchecked)?;

        // - commitment count equals opening count
        checks::check_commitment_and_opening_count_equal(&unchecked)?;

        // - ranges inside one commitment are non-empty, valid, ascending, non-overlapping, non-overflowing
        checks::check_ranges_inside_each_commitment(&unchecked)?;

        // - the length of each opening equals the amount of committed data in the ranges of the
        //   corresponding commitment
        // - the total amount of committed data is less than 1GB to prevent DoS
        checks::check_commitment_sizes(&unchecked)?;

        // - the amount of commitments is less that 1000
        checks::check_commitment_count(&unchecked)?;

        // - overlapping openings must match exactly
        checks::check_overlapping_openings(&unchecked)?;

        // - each [merkle_tree_index] is both unique and also ascending between commitments
        checks::check_merkle_tree_indices(&unchecked);

        Ok(Self {
            version: unchecked.version,
            tls_doc: unchecked.tls_doc,
            signature: unchecked.signature,
            label_seed: unchecked.label_seed,
            merkle_root: unchecked.merkle_root,
            merkle_tree_leaf_count: unchecked.merkle_tree_leaf_count,
            merkle_multi_proof: unchecked.merkle_multi_proof,
            commitments: unchecked.commitments,
            commitment_openings: unchecked.commitment_openings,
        })
    }

    /// verifies the Doc
    pub fn verify(&self, dns_name: String) -> Result<(), Error> {
        // verify the TLS portion of the doc. The cert must contain dns_name
        self.tls_doc.verify(dns_name)?;

        self.verify_merkle_proofs()?;

        self.verify_commitments()?;

        Ok(())
    }

    /// Verifies that each commitment is present in the Merkle tree. Note that we already checked
    /// in [checks::check_merkle_tree_indices] that indices are unique and ascending
    fn verify_merkle_proofs(&self) -> Result<(), Error> {
        // collect all merkle tree leaf indices and corresponding hashes
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
                // corresponding commitment in [VerifierDoc::from_unchecked()]
                _ => return Err(Error::InternalError),
            }
        }

        // verify each (commitment, opening) pair
        for (o, c) in openings.iter().zip(label_commitments) {
            c.verify(o, &self.label_seed)?;
        }

        Ok(())
    }
}

/// This is the [VerifierDoc] in its unchecked form. This is the form in which the doc is received
/// by the Verifier from the User.
pub struct VerifierDocUnchecked {
    /// All fields are exactly as in [VerifierDoc]
    version: u8,
    pub tls_doc: TLSDoc,
    pub signature: Option<Vec<u8>>,
    pub label_seed: LabelSeed,
    pub merkle_root: [u8; 32],
    pub merkle_tree_leaf_count: usize,
    pub merkle_multi_proof: MerkleProof<algorithms::Sha256>,
    pub commitments: Vec<Commitment>,
    pub commitment_openings: Vec<CommitmentOpening>,
}

/// Converts VerifierDoc into an unchecked type with will be passed to the Verifier
impl std::convert::From<VerifierDoc> for VerifierDocUnchecked {
    fn from(doc: VerifierDoc) -> Self {
        Self {
            version: doc.version,
            tls_doc: doc.tls_doc,
            signature: doc.signature,
            label_seed: doc.label_seed,
            merkle_root: doc.merkle_root,
            merkle_tree_leaf_count: doc.merkle_tree_leaf_count,
            merkle_multi_proof: doc.merkle_multi_proof,
            commitments: doc.commitments,
            commitment_openings: doc.commitment_openings,
        }
    }
}
