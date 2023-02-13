use crate::{
    commitment::{Commitment, CommitmentOpening},
    error::Error,
    merkle::MerkleProof,
    tls_handshake::TLSHandshake,
    LabelSeed, PubKey, Signed, ValidatedDoc,
};
use serde::Serialize;

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
            label_seed: *validated_doc.label_seed(),
            merkle_root: *validated_doc.merkle_root(),
            merkle_tree_leaf_count: validated_doc.merkle_tree_leaf_count(),
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

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::{
        commitment::TranscriptRange,
        pubkey::{KeyType, PubKey},
        test::unchecked_doc,
    };
    use rstest::{fixture, rstest};

    #[fixture]
    // Returns a signed validated document and the pubkey used to sign it
    fn signed_validated_doc_and_pubkey() -> (ValidatedDoc, PubKey) {
        // create 2 arbitrary commitments
        let comm1_ranges = vec![
            TranscriptRange::new(5, 15).unwrap(),
            TranscriptRange::new(20, 22).unwrap(),
        ];
        let comm2_ranges = vec![
            TranscriptRange::new(0, 2).unwrap(),
            TranscriptRange::new(15, 20).unwrap(),
        ];
        let (doc, pubkey_bytes, _) = unchecked_doc(vec![comm1_ranges, comm2_ranges]);
        // Initially the Verifier may store the Notary's pubkey as bytes. Converts it into
        // PubKey type
        let trusted_pubkey = PubKey::from_bytes(KeyType::P256, &pubkey_bytes).unwrap();
        (ValidatedDoc::from_unchecked(doc).unwrap(), trusted_pubkey)
    }

    #[rstest]
    // Expect from_validated() to succeed with the correct signature and a pubkey provided
    fn test_from_validated_success_with_sig_and_pubkey(
        signed_validated_doc_and_pubkey: (ValidatedDoc, PubKey),
    ) {
        let validated_doc = signed_validated_doc_and_pubkey.0;
        let trusted_pubkey = signed_validated_doc_and_pubkey.1;

        assert!(
            VerifiedDoc::from_validated(validated_doc, "tlsnotary.org", Some(trusted_pubkey))
                .is_ok()
        );
    }

    #[rstest]
    // Expect from_validated() to succeed when there is no signature and no pubkey provided
    fn test_from_validated_success_no_sig_and_pubkey(
        signed_validated_doc_and_pubkey: (ValidatedDoc, PubKey),
    ) {
        let mut validated_doc = signed_validated_doc_and_pubkey.0;
        validated_doc.set_signature(None);

        assert!(VerifiedDoc::from_validated(validated_doc, "tlsnotary.org", None).is_ok());
    }

    #[rstest]
    // Expect from_validated() to fail when there is no signature but the pubkey is provided
    fn test_from_validated_fail_no_sig(signed_validated_doc_and_pubkey: (ValidatedDoc, PubKey)) {
        let mut validated_doc = signed_validated_doc_and_pubkey.0;
        let trusted_pubkey = signed_validated_doc_and_pubkey.1;

        validated_doc.set_signature(None);

        assert!(
            VerifiedDoc::from_validated(validated_doc, "tlsnotary.org", Some(trusted_pubkey))
                .err()
                .unwrap()
                == Error::NoPubkeyOrSignature
        );
    }

    #[rstest]
    // Expect from_validated() to fail when there is signature but no pubkey is provided
    fn test_from_validated_fail_no_pubkey(signed_validated_doc_and_pubkey: (ValidatedDoc, PubKey)) {
        let validated_doc = signed_validated_doc_and_pubkey.0;

        assert!(
            VerifiedDoc::from_validated(validated_doc, "tlsnotary.org", None)
                .err()
                .unwrap()
                == Error::NoPubkeyOrSignature
        );
    }
}
