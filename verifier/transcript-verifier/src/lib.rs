mod commitment;
mod doc;
mod error;
mod label_encoder;
mod tls_handshake;
mod utils;
pub mod verified_transcript;
mod webpki_utils;

use crate::{
    doc::{unchecked::UncheckedDoc, validated::ValidatedDoc, verified::VerifiedDoc},
    error::Error,
    verified_transcript::VerifiedTranscript,
};
use transcript_core::{document::Document, pubkey::PubKey, signed::Signed};

/// Verifier of the notarization document. The document contains commitments to the TLS
/// transcript.
///
/// Once the verification succeeds, an application level (e.g. HTTP, JSON) parser can
/// parse the resulting transcript [crate::verified_transcript::VerifiedTranscript]
pub struct TranscriptVerifier {}

impl TranscriptVerifier {
    /// Creates a new TranscriptVerifier
    pub fn new() -> Self {
        Self {}
    }

    /// Verifies that the notarization document resulted from notarizing data from a TLS server with the
    /// DNS name `dns_name`. Also verifies the Notary's signature (if any).
    ///
    /// IMPORTANT:
    /// if the notarized application data type is HTTP, the checks below will not be sufficient. You must
    /// also check on the HTTP parser's level against domain fronting.
    ///
    /// * document - The notarization document to be validated and verified
    /// * dns_name - A DNS name. Must be exactly as it appears in the server's TLS certificate.
    /// * signed - If this Verifier acted as the Notary, he provides his [Signed] struct
    /// * trusted_pubkey - A trusted Notary's pubkey (if this Verifier acted as the Notary then no
    ///                    pubkey needs to be provided)
    pub fn verify(
        &self,
        document: Document,
        dns_name: &str,
        trusted_pubkey: Option<PubKey>,
        signed: Option<Signed>,
    ) -> Result<VerifiedTranscript, Error> {
        // convert the user's document into a document with types which can be validated
        // and verified
        let unchecked_doc = UncheckedDoc::from(document);

        // validate the document
        let validated_doc = match signed {
            None => ValidatedDoc::from_unchecked(unchecked_doc)?,
            Some(signed) => ValidatedDoc::from_unchecked_with_signed_data(unchecked_doc, signed)?,
        };

        // verify the document
        let verified_doc = VerifiedDoc::from_validated(validated_doc, dns_name, trusted_pubkey)?;

        // extract the verified transcript
        let verified_transcript = VerifiedTranscript::from_verified_doc(verified_doc, dns_name);

        Ok(verified_transcript)
    }
}

#[cfg(test)]
mod test {
    use crate::doc::unchecked::UncheckedDoc;
    use blake3::Hasher;
    use transcript_core::{
        commitment::{
            CommitmentOpening, CommitmentType, Direction, LabelsBlake3Opening, TranscriptRange,
        },
        document::Document,
        merkle::MerkleProof,
        signed::{Signed, SignedHandshake},
        tls_handshake::{
            EphemeralECPubkey, EphemeralECPubkeyType, HandshakeData, KEParamsSigAlg,
            ServerSignature, TLSHandshake,
        },
        HashCommitment, LabelSeed,
    };

    use mpc_circuits::Value;
    use mpc_core::garble::{ChaChaEncoder, Encoder, Label};
    use p256::ecdsa::{signature::Signer, SigningKey, VerifyingKey};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha12Rng;
    use rs_merkle::{algorithms::Sha256, MerkleTree};
    use tls_circuits::c6;

    // the leaves of the tree with indices [1..8] will have a dummy value
    pub const DUMMY_HASH: [u8; 32] = [0u8; 32];

    // unix time when the cert chain was valid
    pub const TIME: u64 = 1671637529;

    // plaintext padded to a multiple of 16 bytes
    pub const DEFAULT_PLAINTEXT: [u8; 48] = *b"This important data will be notarized...........";

    /// Returns default ranges which are used to construct the default document
    pub fn default_ranges() -> Vec<TranscriptRange> {
        vec![
            // sent data commitment's ranges
            TranscriptRange::new(5, 20).unwrap(),
            TranscriptRange::new(20, 22).unwrap(),
            // received data commitment's ranges
            TranscriptRange::new(0, 2).unwrap(),
            TranscriptRange::new(15, 20).unwrap(),
        ]
    }

    /// Constructs a default signed unchecked document with the provided commitments. Returns the doc, the pubkey
    /// used to sign it, and the Signed portion of the doc.
    pub fn default_unchecked_doc() -> (UncheckedDoc, Vec<u8>, Signed) {
        let ranges = default_ranges();
        let comm1_ranges = vec![ranges[0].clone(), ranges[1].clone()];
        let comm2_ranges = vec![ranges[2].clone(), ranges[3].clone()];
        unchecked_doc(vec![comm1_ranges, comm2_ranges])
    }

    /// Constructs a signed unchecked document with the provided commitment ranges. Returns the doc,
    /// the pubkey used to sign it, and the Signed portion of the doc.
    pub fn unchecked_doc(
        // 2 ranges for the first commitment and 2 ranges for the second commitment
        commitment_ranges: Vec<Vec<TranscriptRange>>,
    ) -> (UncheckedDoc, Vec<u8>, Signed) {
        if commitment_ranges.len() != 2 {
            panic!("two commitments are expected")
        }
        let mut rng = ChaCha12Rng::from_seed([0; 32]);

        // -------- After the webserver sends the Server Key Exchange message (during the TLS handshake),
        //          the tls-client module provides the following TLS data:

        /// end entity cert
        static EE: &[u8] = include_bytes!("testdata/tlsnotary.org/ee.der");
        // intermediate cert
        static INTER: &[u8] = include_bytes!("testdata/tlsnotary.org/inter.der");
        // certificate authority cert
        static CA: &[u8] = include_bytes!("testdata/tlsnotary.org/ca.der");
        let cert_chain = vec![CA.to_vec(), INTER.to_vec(), EE.to_vec()];

        // data taken from an actual network trace captured with `tcpdump host tlsnotary.org -w out.pcap`
        // (see testdata/key_exchange/README for details)

        let client_random =
            hex::decode("ac3808970faf996d38864e205c6b787a1d05f681654a5d2a3c87f7dd2f13332e")
                .unwrap();
        let server_random =
            hex::decode("8abf9a0c4b3b9694edac3d19e8eb7a637bfa8fe5644bd9f1444f574e47524401")
                .unwrap();
        let ephemeral_pubkey = hex::decode("04521e456448e6156026bb1392e0a689c051a84d67d353ab755fce68a2e9fba68d09393fa6485db84517e16d9855ce5ba3ec2293f2e511d1e315570531722e9788").unwrap();
        let sig = hex::decode("337aa65793562550f6de0a9c792b5f531a96bb78f65a2063f710bfb99e11c791e13d35c798b50eea1351c14efc526009c7836e888206cebde7135130a1fbc049d42e1d1ed05c10f0d108b9540f049ac24fe1076d391b9da3d4e60b5cb8f341bda993f6002873847be744c1955ff575b2d833694fb8a432898c5ac55752e2bddcee4c07371335e1a6581694df43c6eb0ce8da4cdd497c205607b573f9c5d17c951e0a71fbf967c4bff53fc37c597b2f5656478fefb780e8f37bd8409985dd980eda4f254c7dce76dc69e66ed27c0f2c93b53a6dfd7b27359e1589a30d483725e92305766c62d6cad2c0142d3a3c4a2272e6d81eda2886ef12028167f83b3c33ea").unwrap();

        let server_sig = ServerSignature::new(KEParamsSigAlg::RSA_PKCS1_2048_8192_SHA256, sig);

        let ephemeral_pubkey =
            EphemeralECPubkey::new(EphemeralECPubkeyType::P256, ephemeral_pubkey);

        // -------- Using the above data, the User computes [HandshakeData] and sends a commitment to
        //          the Notary

        let handshake_data =
            HandshakeData::new(cert_chain, server_sig, client_random, server_random);
        let handshake_commitment = blake3(&handshake_data.serialize().unwrap());

        // -------- The Notary generates garbled circuit's labels from a PRG seed (label_seed which
        //          was passed in).

        // ---------- After the notarization session is over and after the Notary revealed his label_seed:

        let label_seed: LabelSeed = rng.gen();
        let mut enc = ChaChaEncoder::new(label_seed);

        // encoder works only on the `Input` type. This is the only way to obtain it
        // c6 is the AES encryption circuit, input with id == 4 is the plaintext
        let input = c6().input(4).unwrap();

        // since `input` is a 16-byte value, encode one 16-byte chunk at a time
        let active_labels: Vec<Label> = DEFAULT_PLAINTEXT
            .chunks(16)
            .flat_map(|chunk| {
                let full_labels = enc.encode(4, &input, false);
                // construct a Value type
                let v = Value::from(chunk.to_vec());
                // get active labels
                let active = full_labels.select(&v).unwrap();
                let flat: Vec<Label> = active.iter().collect();
                flat
            })
            .collect();

        // -------- The User computes all her (salted) commitments

        let salt: [u8; 32] = rng.gen();

        // The User expands label_seed to obtain all labels, then hashes all the active labels (salted)
        // in the commitment's ranges (the result is `hash_commitments` which was passed in)

        let mut hash_commitments: Vec<HashCommitment> = Vec::with_capacity(commitment_ranges.len());

        for ranges in &commitment_ranges {
            // hash all the active labels in the commitment's ranges
            let mut hasher = Hasher::new();

            for r in ranges {
                for label in active_labels[(r.start() * 8) as usize..(r.end() * 8) as usize].iter()
                {
                    hasher.update(&label.into_inner().to_be_bytes());
                }
            }

            // add salt
            hasher.update(&salt);
            hash_commitments.push(hasher.finalize().into());
        }

        let comm1 = transcript_core::commitment::Commitment::new(
            0,
            CommitmentType::labels_blake3,
            Direction::Sent,
            hash_commitments[0],
            commitment_ranges[0].clone(),
            0,
        );

        let comm2 = transcript_core::commitment::Commitment::new(
            1,
            CommitmentType::labels_blake3,
            Direction::Received,
            hash_commitments[1],
            commitment_ranges[1].clone(),
            9,
        );

        // -------- The User creates a merkle tree of commitments and then a merkle proof of inclusion.
        //          Sends the merkle_root to the Notary

        // fill with 8 random leaves between index 0 and 10
        let dummy8 = [DUMMY_HASH; 8];
        let leaves = [
            [hash_commitments[0]].to_vec(),
            dummy8.to_vec(),
            [hash_commitments[1]].to_vec(),
        ]
        .concat();
        let merkle_tree = MerkleTree::<Sha256>::from_leaves(&leaves);
        let merkle_root = merkle_tree.root().unwrap();

        // -------- the Notary uses his pubkey to compute a signature
        let signing_key = SigningKey::random(&mut rng);
        let verifying_key = VerifyingKey::from(&signing_key);
        let encoded = verifying_key.to_encoded_point(true);
        let pubkey_bytes = encoded.as_bytes();

        // (note that `ephemeral_pubkey` is known both to the User and the Notary)
        let signed_handshake = SignedHandshake::new(TIME, ephemeral_pubkey, handshake_commitment);
        let signed = Signed::new(signed_handshake.clone(), label_seed, merkle_root);

        let signature = signing_key.sign(&bincode::serialize(&signed).unwrap());
        let sig_der = signature.to_der();
        let signature = sig_der.as_bytes();

        // -------- the Notary reveals `label_seed` and also sends the `signature` and `time`.

        // -------- After that the User creates a doc for the Verifier:
        //          (The User creates `signed_handshake` just like the Notary did above)
        let tls_handshake = TLSHandshake::new(signed_handshake, handshake_data);

        // prepares openings and merkle proofs for those openings
        let opening1_bytes = bytes_in_ranges(&DEFAULT_PLAINTEXT, commitment_ranges[0].as_ref());
        let open1 = CommitmentOpening::LabelsBlake3(LabelsBlake3Opening::new(
            0,
            opening1_bytes,
            salt.to_vec(),
            label_seed,
        ));

        let opening2_bytes = bytes_in_ranges(&DEFAULT_PLAINTEXT, commitment_ranges[1].as_ref());
        let open2 = CommitmentOpening::LabelsBlake3(LabelsBlake3Opening::new(
            1,
            opening2_bytes,
            salt.to_vec(),
            label_seed,
        ));

        let indices_to_prove = [
            comm1.merkle_tree_index() as usize,
            comm2.merkle_tree_index() as usize,
        ];
        let proof = MerkleProof(merkle_tree.proof(&indices_to_prove));

        let doc = Document::new(
            1,
            tls_handshake,
            Some(signature.to_vec()),
            label_seed,
            merkle_root,
            10,
            proof,
            vec![comm1, comm2],
            vec![open1, open2],
        );

        (doc.into(), pubkey_bytes.to_vec(), signed)
    }

    /// Returns a substring of the original `bytestring` containing only the bytes in `ranges`.
    /// This method is only called with validated `ranges` which do not exceed the size of the
    /// `bytestring`.
    pub(crate) fn bytes_in_ranges(bytestring: &[u8], ranges: &[TranscriptRange]) -> Vec<u8> {
        let mut substring: Vec<u8> = Vec::new();
        for r in ranges {
            substring.append(&mut bytestring[r.start() as usize..r.end() as usize].to_vec())
        }
        substring
    }

    /// Outputs blake3 digest
    fn blake3(data: &[u8]) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(data);
        hasher.finalize().into()
    }
}
