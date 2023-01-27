mod checks;
mod commitment;
mod error;
mod label_encoder;
mod pubkey;
mod signed;
mod tls_doc;
mod utils;
mod verifier_doc;
mod webpki_utils;

use crate::signed::Signed;
use error::Error;
use pubkey::PubKey;
use verifier_doc::{VerifierDoc, VerifierDocUnchecked};

type HashCommitment = [u8; 32];

/// A PRG seeds from which to generate garbled circuit active labels, see
/// [crate::commitment::CommitmentType::labels_blake3]
type LabelSeed = [u8; 32];

/// Verifier of the notarization document
///
/// Once the verification succeeds, an application level (e.g. HTTP, JSON) parser can
/// parse `commitment_openings` in `doc`
pub struct Verifier {
    /// A validated notarization document which needs to be verified
    doc: VerifierDoc,
    /// A trusted Notary's pubkey (if this Verifier acted as the Notary then no pubkey needs
    /// to be provided)
    trusted_pubkey: Option<PubKey>,
}

impl Verifier {
    /// Validates the notarization document and creates a new Verifier
    pub fn new(
        doc_unchecked: VerifierDocUnchecked,
        trusted_pubkey: Option<PubKey>,
    ) -> Result<Self, Error> {
        let doc = VerifierDoc::from_unchecked(doc_unchecked)?;
        Ok(Self {
            doc,
            trusted_pubkey,
        })
    }

    /// Verifies that the notarization document resulted from notarizing data from a TLS server with the
    /// DNS name `dns_name`. `dns_name` must be exactly as it appears in the server's TLS certificate.
    /// Also verifies the Notary's signature (if any).
    ///
    /// IMPORTANT:
    /// if the notarized application data is HTTP, the checks below will not be sufficient. You must also
    /// check on the HTTP parser's level against domain fronting.
    ///
    pub fn verify(&self, dns_name: String) -> Result<(), Error> {
        // verify Notary's signature, if any
        match (self.doc.signature(), &self.trusted_pubkey) {
            (Some(sig), Some(pubkey)) => {
                self.verify_doc_signature(pubkey, sig)?;
            }
            // no pubkey and no signature, do nothing
            (None, None) => (),
            // either pubkey or signature is missing
            _ => {
                return Err(Error::NoPubkeyOrSignature);
            }
        }

        // verify the document
        self.doc.verify(dns_name)?;

        Ok(())
    }

    /// Verifies Notary's signature on that part of the document which was signed
    fn verify_doc_signature(&self, pubkey: &PubKey, sig: &[u8]) -> Result<(), Error> {
        let msg = self.signed_data().serialize()?;
        pubkey.verify_signature(&msg, sig)
    }

    /// Extracts the necessary fields from the [VerifierDoc] into a [Signed]
    /// struct and returns it
    fn signed_data(&self) -> Signed {
        (&self.doc).into()
    }
}

#[test]
// Create a document and verify it
fn e2e_test() {
    use crate::{
        commitment::{Commitment, CommitmentOpening, CommitmentType, Direction, Range},
        label_encoder::{Block, ChaChaEncoder},
        signed::SignedTLS,
        tls_doc::{
            CommittedTLS, EphemeralECPubkey, EphemeralECPubkeyType, KEParamsSigAlg,
            ServerSignature, TLSDoc,
        },
        utils::{blake3, bytes_in_ranges, u8vec_to_boolvec},
        Signed,
    };
    use blake3::Hasher;
    use p256::ecdsa::{signature::Signer, SigningKey, VerifyingKey};
    use pubkey::KeyType;
    use rand::Rng;
    use rs_merkle::{algorithms::Sha256, MerkleTree};

    let mut rng = rand::thread_rng();

    let plaintext = b"This important data will be notarized";

    // -------- After the webserver sends the Server Key Exchange message (during the TLS handshake),
    //          the tls-client module provides the following TLS data:

    /// end entity cert
    static EE: &[u8] = include_bytes!("testdata/tlsnotary.org/ee.der");
    // intermediate cert
    static INTER: &[u8] = include_bytes!("testdata/tlsnotary.org/inter.der");
    // certificate authority cert
    static CA: &[u8] = include_bytes!("testdata/tlsnotary.org/ca.der");
    let cert_chain = vec![CA.to_vec(), INTER.to_vec(), EE.to_vec()];
    // unix time when the cert chain was valid
    static TIME: u64 = 1671637529;

    // data taken from an actual network trace captured with `tcpdump host tlsnotary.org -w out.pcap`
    // (see testdata/key_exchange/README for details)

    let client_random =
        hex::decode("ac3808970faf996d38864e205c6b787a1d05f681654a5d2a3c87f7dd2f13332e").unwrap();
    let server_random =
        hex::decode("8abf9a0c4b3b9694edac3d19e8eb7a637bfa8fe5644bd9f1444f574e47524401").unwrap();
    let ephemeral_pubkey = hex::decode("04521e456448e6156026bb1392e0a689c051a84d67d353ab755fce68a2e9fba68d09393fa6485db84517e16d9855ce5ba3ec2293f2e511d1e315570531722e9788").unwrap();
    let sig = hex::decode("337aa65793562550f6de0a9c792b5f531a96bb78f65a2063f710bfb99e11c791e13d35c798b50eea1351c14efc526009c7836e888206cebde7135130a1fbc049d42e1d1ed05c10f0d108b9540f049ac24fe1076d391b9da3d4e60b5cb8f341bda993f6002873847be744c1955ff575b2d833694fb8a432898c5ac55752e2bddcee4c07371335e1a6581694df43c6eb0ce8da4cdd497c205607b573f9c5d17c951e0a71fbf967c4bff53fc37c597b2f5656478fefb780e8f37bd8409985dd980eda4f254c7dce76dc69e66ed27c0f2c93b53a6dfd7b27359e1589a30d483725e92305766c62d6cad2c0142d3a3c4a2272e6d81eda2886ef12028167f83b3c33ea").unwrap();

    let server_sig = ServerSignature::new(KEParamsSigAlg::RSA_PKCS1_2048_8192_SHA256, sig);

    let ephemeral_pubkey = EphemeralECPubkey::new(EphemeralECPubkeyType::P256, ephemeral_pubkey);

    // -------- Using the above data, the User computes [CommittedTLS] and sends a commitment to
    //          the Notary

    let committed_tls = CommittedTLS::new(cert_chain, server_sig, client_random, server_random);
    let commitment_to_tls = blake3(&committed_tls.serialize().unwrap());

    // -------- The Notary generates garbled circuit's labels from a PRG seed. One pair of labels
    //          for each bit of plaintext

    let label_seed: LabelSeed = rng.gen();

    let mut enc = ChaChaEncoder::new(label_seed);

    // Note that for this test's purposes the Notary is using crate::label_encoder.
    // In production he will use tlsn/mpc/mpc-core/garble/label/encoder
    let full_labels: Vec<[Block; 2]> = (0..plaintext.len() * 8).map(|i| enc.encode(i)).collect();

    // -------- The User retrieves her active labels using Oblivious Transfer (simulated below):

    // convert plaintext into lsb0 bits
    let bits = u8vec_to_boolvec(plaintext);

    let all_active_labels: Vec<Block> = full_labels
        .iter()
        .zip(bits)
        .map(
            |(label_pair, bit)| {
                if bit {
                    label_pair[1]
                } else {
                    label_pair[0]
                }
            },
        )
        .collect();

    // ---------- After the notar. session is over: --------

    // -------- The User computes all her commitments

    // Here we'll have 1 (salted) commitment which has 1 range

    let ranges = vec![Range::new(5, 19).unwrap()];

    let salt: [u8; 32] = rng.gen();

    // hash all the active labels in the commitment's ranges
    let mut hasher = Hasher::new();

    for r in &ranges {
        for label in all_active_labels[r.start() * 8..r.end() * 8].iter() {
            hasher.update(&label.inner().to_be_bytes());
        }
    }

    // add salt
    hasher.update(&salt);
    let hash_commitment: HashCommitment = hasher.finalize().into();

    let comm = Commitment::new(
        0,
        CommitmentType::labels_blake3,
        Direction::Sent,
        hash_commitment,
        ranges.clone(),
        0,
    );

    // -------- The User creates a merkle tree of commitments and then a merkle proof of inclusion.
    //          Sends the merkle_root to the Notary
    let leaves = [hash_commitment];
    let merkle_tree = MerkleTree::<Sha256>::from_leaves(&leaves);
    let merkle_root = merkle_tree.root().unwrap();

    // -------- the Notary uses his pubkey to compute a signature
    let signing_key = SigningKey::random(&mut rng);
    let verifying_key = VerifyingKey::from(&signing_key);
    let encoded = verifying_key.to_encoded_point(true);
    let pubkey_bytes = encoded.as_bytes();

    // (note that ephemeralECPubkey is known both to the User and the Notary)
    let signed_tls = SignedTLS::new(TIME, ephemeral_pubkey, commitment_to_tls);
    let signed = Signed::new(signed_tls.clone(), label_seed, merkle_root);

    let signature = signing_key.sign(&bincode::serialize(&signed).unwrap());
    let sig_der = signature.to_der();
    let signature = sig_der.as_bytes();

    // -------- the Notary reveals `label_seed` and also sends the `signature` and `time`.

    // -------- After that the User creates a doc for the Verifier:
    //          (The User creates `signed_tls` just like the Notary did above)
    let tls_doc = TLSDoc::new(signed_tls, committed_tls);

    // prepares openings and merkle proofs for those openings
    let opening_bytes = bytes_in_ranges(plaintext, &ranges);
    let open = CommitmentOpening::new(0, opening_bytes, salt.to_vec());

    let indices_to_prove = vec![0];
    let proof = merkle_tree.proof(&indices_to_prove);

    let doc = VerifierDoc::new(
        1,
        tls_doc,
        Some(signature.to_vec()),
        label_seed,
        merkle_root,
        1,
        proof,
        vec![comm],
        vec![open],
    );

    // -------- The User converts the doc into an unchecked type and passes it to the Verifier
    let doc_unchecked: VerifierDocUnchecked = doc.into();

    // -------- The Verifier verifies the doc:

    // Initially the Verifier may store the Notary's pubkey as bytes. Converts it into
    // PubKey type
    let trusted_pubkey = PubKey::from_bytes(KeyType::P256, pubkey_bytes).unwrap();

    let verifier = Verifier::new(doc_unchecked, Some(trusted_pubkey)).unwrap();

    verifier.verify("tlsnotary.org".to_string()).unwrap();

    // -------- The Verifier proceeds to put each verified commitment opening through an application
    //          level (e.g. http) parser

    assert_eq!(
        String::from_utf8(verifier.doc.commitment_openings()[0].opening().clone()).unwrap(),
        "important data".to_string()
    );
}
