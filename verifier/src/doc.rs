use super::{
    checks,
    commitment::{Commitment, CommitmentOpening, CommitmentType},
    error::Error,
    tls_handshake::TLSHandshake,
    LabelSeed, Signed,
};
use rs_merkle::{algorithms, proof_serializers, MerkleProof};
use serde::{ser::Serializer, Serialize};
use std::{any::Any, collections::HashMap};

#[derive(Serialize)]
/// A validated and verified notarization document
pub struct VerifiedDoc {
    version: u8,
    tls_handshake: TLSHandshake,
    /// Notary's signature over the [Signed] portion of this doc
    signature: Option<Vec<u8>>,

    /// A PRG seeds from which to generate garbled circuit active labels, see
    /// [crate::commitment::CommitmentType::labels_blake3]
    label_seed: LabelSeed,

    /// The root of the Merkle tree of all the commitments. The User must prove that each one of the
    /// `commitments` is included in the Merkle tree.
    /// This approach allows the User to hide from the Notary the exact amount of commitments thus
    /// increasing User privacy against the Notary.
    /// The root was made known to the Notary before the Notary opened his garbled circuits
    /// to the User.
    merkle_root: [u8; 32],

    /// The total leaf count in the Merkle tree of commitments. Provided by the User to the Verifier
    /// to enable merkle proof verification.
    merkle_tree_leaf_count: u32,

    /// A proof that all [commitments] are the leaves of the Merkle tree
    #[serde(serialize_with = "merkle_proof_serialize")]
    merkle_multi_proof: MerkleProof<algorithms::Sha256>,

    /// User's commitments to various portions of the notarized data, sorted ascendingly by id
    commitments: Vec<Commitment>,

    /// Openings for the commitments, sorted ascendingly by id
    commitment_openings: Vec<CommitmentOpening>,
}

impl VerifiedDoc {
    /// Creates a new [VerifiedDoc] from [ValidatedDoc]
    pub(crate) fn from_validated(validated: ValidatedDoc) -> Self {
        Self {
            version: validated.version,
            tls_handshake: validated.tls_handshake,
            signature: validated.signature,
            label_seed: validated.label_seed,
            merkle_root: validated.merkle_root,
            merkle_tree_leaf_count: validated.merkle_tree_leaf_count,
            merkle_multi_proof: validated.merkle_multi_proof,
            commitments: validated.commitments,
            commitment_openings: validated.commitment_openings,
        }
    }

    pub fn tls_handshake(&self) -> &TLSHandshake {
        &self.tls_handshake
    }

    pub fn commitments(&self) -> &Vec<Commitment> {
        &self.commitments
    }

    pub fn commitment_openings(&self) -> &Vec<CommitmentOpening> {
        &self.commitment_openings
    }
}

/// Notarization document in its unchecked form. This is the form in which the document is received
/// by the Verifier from the User.
pub struct UncheckedDoc {
    /// All fields are exactly as in [VerifiedDoc]
    version: u8,
    tls_handshake: TLSHandshake,
    signature: Option<Vec<u8>>,
    label_seed: LabelSeed,
    merkle_root: [u8; 32],
    merkle_tree_leaf_count: u32,
    merkle_multi_proof: MerkleProof<algorithms::Sha256>,
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
        merkle_multi_proof: MerkleProof<algorithms::Sha256>,
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

    pub fn commitments(&self) -> &Vec<Commitment> {
        &self.commitments
    }

    pub fn commitment_openings(&self) -> &Vec<CommitmentOpening> {
        &self.commitment_openings
    }
}

/// Notarization document in its validated form (not yet verified)
pub(crate) struct ValidatedDoc {
    /// All fields are exactly as in [VerifiedDoc]
    version: u8,
    tls_handshake: TLSHandshake,
    signature: Option<Vec<u8>>,
    label_seed: LabelSeed,
    merkle_root: [u8; 32],
    merkle_tree_leaf_count: u32,
    merkle_multi_proof: MerkleProof<algorithms::Sha256>,
    commitments: Vec<Commitment>,
    commitment_openings: Vec<CommitmentOpening>,
}

impl ValidatedDoc {
    /// Returns a new [ValidatedDoc] after performing all validation checks
    pub(crate) fn from_unchecked(unchecked: UncheckedDoc) -> Result<Self, Error> {
        checks::perform_checks(&unchecked)?;

        // Make sure the Notary's signature is present.
        // (If the Verifier IS also the Notary then the signature is NOT needed. `VerifiedDoc`
        // should be created with `from_unchecked_with_signed_data()` instead.)

        if unchecked.signature.is_none() {
            return Err(Error::SignatureExpected);
        }

        Ok(Self {
            version: unchecked.version,
            tls_handshake: unchecked.tls_handshake,
            signature: unchecked.signature,
            label_seed: unchecked.label_seed,
            merkle_root: unchecked.merkle_root,
            merkle_tree_leaf_count: unchecked.merkle_tree_leaf_count,
            merkle_multi_proof: unchecked.merkle_multi_proof,
            commitments: unchecked.commitments,
            commitment_openings: unchecked.commitment_openings,
        })
    }

    /// Returns a new [ValidatedDoc] after performing all validation checks and adding the signed data.
    /// `signed_data` (despite its name) is not actually signed because it was generated locally by
    /// the calling Verifier.
    pub(crate) fn from_unchecked_with_signed_data(
        unchecked: UncheckedDoc,
        signed_data: Signed,
    ) -> Result<Self, Error> {
        checks::perform_checks(&unchecked)?;

        // Make sure the Notary's signature is NOT present.
        // (If the Verifier is NOT the Notary then the Notary's signature IS needed. `ValidatedDoc`
        // should be created with `from_unchecked()` instead.)

        if unchecked.signature.is_some() {
            return Err(Error::SignatureNotExpected);
        }

        // insert our `signed_data` which we know is correct

        let tls_handshake = TLSHandshake::new(
            signed_data.tls().clone(),
            unchecked.tls_handshake.handshake_data().clone(),
        );
        let label_seed = *signed_data.label_seed();
        let merkle_root = *signed_data.merkle_root();

        Ok(Self {
            version: unchecked.version,
            tls_handshake,
            signature: unchecked.signature,
            label_seed,
            merkle_root,
            merkle_tree_leaf_count: unchecked.merkle_tree_leaf_count,
            merkle_multi_proof: unchecked.merkle_multi_proof,
            commitments: unchecked.commitments,
            commitment_openings: unchecked.commitment_openings,
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
        if !self.merkle_multi_proof.verify(
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
            openings_ids.insert(o.id() as usize, o);
        }

        // collect only openings corresponding to label commitments
        let mut openings: Vec<&CommitmentOpening> = Vec::with_capacity(label_commitments.len());
        for c in &label_commitments {
            match openings_ids.get(&(c.id() as usize)) {
                Some(opening) => openings.push(opening),
                // should never happen since we already checked that each opening has a
                // corresponding commitment in [super::checks::check_commitment_and_opening_ids()]
                _ => return Err(Error::InternalError),
            }
        }

        // verify each (opening, commitment) pair
        for (o, c) in openings.iter().zip(label_commitments) {
            c.verify(o, Box::new(self.label_seed) as Box<dyn Any>)?;
        }

        Ok(())
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

    pub fn tls_handshake(&self) -> &TLSHandshake {
        &self.tls_handshake
    }
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