use crate::{
    commitment::{Commitment, CommitmentOpening, CommitmentType},
    error::Error,
    merkle::MerkleProof,
    tls_handshake::TLSHandshake,
    LabelSeed, PubKey, Signed, ValidatedDoc,
};
use serde::{ser::Serializer, Serialize};
use std::collections::HashMap;

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
    merkle_multi_proof: MerkleProof,

    /// User's commitments to various portions of the notarized data, sorted ascendingly by id
    commitments: Vec<Commitment>,

    /// Openings for the commitments, sorted ascendingly by id
    commitment_openings: Vec<CommitmentOpening>,
}

impl VerifiedDoc {
    /// Creates a new [VerifiedDoc] from [ValidatedDoc]
    pub(crate) fn from_validated(
        validated_doc: ValidatedDoc,
        dns_name: &str,
        trusted_pubkey: Option<PubKey>,
    ) -> Result<Self, Error> {
        // verify Notary's signature, if any
        match (validated_doc.signature(), &trusted_pubkey) {
            (Some(sig), Some(pubkey)) => {
                verify_doc_signature(pubkey, sig, signed_data(&validated_doc))?;
            }
            // no pubkey and no signature (this Verifier was also the Notary), do not verify
            (None, None) => {}
            // either pubkey or signature is missing
            _ => {
                return Err(Error::NoPubkeyOrSignature);
            }
        }

        // verify the document
        validated_doc.verify(dns_name)?;

        Ok(Self {
            version: validated_doc.version(),
            tls_handshake: validated_doc.tls_handshake().clone(),
            signature: validated_doc.signature().clone(),
            label_seed: validated_doc.label_seed().clone(),
            merkle_root: validated_doc.merkle_root().clone(),
            merkle_tree_leaf_count: validated_doc.merkle_tree_leaf_count().clone(),
            merkle_multi_proof: validated_doc.merkle_multi_proof().clone(),
            commitments: validated_doc.commitments().clone(),
            commitment_openings: validated_doc.commitment_openings().clone(),
        })
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

/// Verifies Notary's signature on that part of the document which was signed
pub(crate) fn verify_doc_signature(pubkey: &PubKey, sig: &[u8], msg: Signed) -> Result<(), Error> {
    let msg = msg.serialize()?;
    pubkey.verify_signature(&msg, sig)
}

/// Extracts the necessary fields from the [ValidatedDoc] into a [Signed]
/// struct and returns it
pub(crate) fn signed_data(doc: &ValidatedDoc) -> Signed {
    doc.into()
}
