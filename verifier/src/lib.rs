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
use blake3::Hasher;
use error::Error;
use pubkey::PubKey;
use verifier_doc::{VerifierDoc, VerifierDocUnchecked};

type HashCommitment = [u8; 32];

struct VerifierCore {
    /// notarization doc which needs to be verified
    doc: VerifierDoc,
    /// trusted notary's pubkey. If this Verifier is also the Notary then no pubkey needs
    /// to be provided, the signature on the [crate::main_doc::MainDoc] will not be checked.
    trusted_pubkey: Option<PubKey>,
}

/// Verifies the core aspects of the notarization session: the Notary signature, the TLS
/// authenticity and the correctness of commitments and zk proofs.
///
/// After the verification completes, the application level (e.g. HTTP) parser can start
/// parsing the openings in [VerifierDoc::commitment_openings]
impl VerifierCore {
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

    /// verifies that the session in the VerifierDoc came from the server with the dns_name
    ///
    /// Note that the checks below are not sufficient to establish data provenance.
    /// There also must be a check done on the HTTP level against the domain fronting
    /// attack.
    pub fn verify(&self, dns_name: String) -> Result<(), Error> {
        // verify the Notary signature, if any
        match (&self.doc.signature, &self.trusted_pubkey) {
            (Some(sig), Some(pubkey)) => {
                self.verify_doc_signature(pubkey, sig, &self.signed_data())?;
            }
            // no pubkey and no signature, do nothing
            (None, None) => (),
            // either pubkey or sig is missing
            _ => {
                return Err(Error::NoPubkeyOrSignature);
            }
        }

        // verify all other aspects of notarization
        self.doc.verify(dns_name)?;

        Ok(())
    }

    // verify Notary's sig on the notarization doc
    fn verify_doc_signature(
        &self,
        pubkey: &PubKey,
        sig: &[u8],
        msg: &Signed,
    ) -> Result<bool, Error> {
        let serialized = bincode::serialize(&msg).unwrap();
        Ok(pubkey.verify_signature(&serialized, sig))
    }

    // extracts the necessary data from the VerifierDoc into a Signed
    // struct and returns it
    fn signed_data(&self) -> Signed {
        //let doc = &self.doc.clone();
        (&self.doc).into()
    }
}

/// A PRG seeds from which to generate Notary's circuits' input labels for one
/// direction. We will use 2 separate seeds: one to generate the labels for all
/// plaintext which was sent and another seed to generate the labels for all plaintext
/// which was received
type LabelSeed = [u8; 32];

pub fn blake3(data: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[test]
fn e2e_test() {
    use crate::{
        commitment::{Commitment, CommitmentOpening, CommitmentType, Direction, Range},
        signed::SignedTLS,
        tls_doc::{
            CommittedTLS, EphemeralECPubkey, EphemeralECPubkeyType, SigKEParamsAlg,
            SignatureKeyExchangeParams, TLSDoc,
        },
        utils::bytes_in_ranges,
        Signed,
    };
    use p256::ecdsa::{signature::Signer, SigningKey, VerifyingKey};
    use pubkey::KeyType;
    use rand::Rng;
    use rs_merkle::{algorithms::Sha256, MerkleTree};

    let mut rng = rand::thread_rng();

    // After the webserver sends the Server Key Exchange message (during the TLS handshake),
    // the tls-client module provides the following TLS data:

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

    let cr =
        hex::decode("ac3808970faf996d38864e205c6b787a1d05f681654a5d2a3c87f7dd2f13332e").unwrap();
    let sr =
        hex::decode("8abf9a0c4b3b9694edac3d19e8eb7a637bfa8fe5644bd9f1444f574e47524401").unwrap();
    let eph_pk = hex::decode("04521e456448e6156026bb1392e0a689c051a84d67d353ab755fce68a2e9fba68d09393fa6485db84517e16d9855ce5ba3ec2293f2e511d1e315570531722e9788").unwrap();
    let sig = hex::decode("337aa65793562550f6de0a9c792b5f531a96bb78f65a2063f710bfb99e11c791e13d35c798b50eea1351c14efc526009c7836e888206cebde7135130a1fbc049d42e1d1ed05c10f0d108b9540f049ac24fe1076d391b9da3d4e60b5cb8f341bda993f6002873847be744c1955ff575b2d833694fb8a432898c5ac55752e2bddcee4c07371335e1a6581694df43c6eb0ce8da4cdd497c205607b573f9c5d17c951e0a71fbf967c4bff53fc37c597b2f5656478fefb780e8f37bd8409985dd980eda4f254c7dce76dc69e66ed27c0f2c93b53a6dfd7b27359e1589a30d483725e92305766c62d6cad2c0142d3a3c4a2272e6d81eda2886ef12028167f83b3c33ea").unwrap();

    let params = SignatureKeyExchangeParams::new(SigKEParamsAlg::RSA_PKCS1_2048_8192_SHA256, sig);

    let eph_ec = EphemeralECPubkey::new(EphemeralECPubkeyType::P256, eph_pk);

    // Using the above data, the User computes [CommittedTLS] and sends a commitment to the Notary

    let committed_tls = CommittedTLS::new(cert_chain, params, cr, sr);
    let commitment_to_tls = blake3(&bincode::serialize(&committed_tls).unwrap());

    // ---------- After the notar. session is over:

    // The User computes all her commitments
    // Here we'll have 1 (salted) commitment which has 1 byterange

    let plaintext = b"This data will be notarized";
    let ranges = vec![Range::new(2, 8)];
    let salt: [u8; 32] = rng.gen(); //TODO change to random salt

    // Note that the User will NOT be actually calling compute_label_commitment(). He doesn't
    // have label_seed at this point of the protocol. Instead, the User will
    // flatten all his active labels, select those which are located within ranges and will
    // hash them.
    //
    let label_seed = rng.gen();
    let hash_commitment =
        utils::compute_label_commitment(plaintext, &label_seed, &ranges, salt.to_vec()).unwrap();

    let comm = Commitment::new(
        0,
        CommitmentType::labels_blake3,
        Direction::Request,
        hash_commitment,
        ranges.clone(),
        0,
    );

    // The User creates a merkle tree of commitments and then a merkle proof of inclusion.
    // Sends the merkle_root to the Notary
    let leaves = [hash_commitment];
    let merkle_tree = MerkleTree::<Sha256>::from_leaves(&leaves);
    let merkle_root = merkle_tree.root().unwrap();

    // the Notary uses his pubkey to compute a signature
    let signing_key = SigningKey::random(&mut rng);
    let verifying_key = VerifyingKey::from(&signing_key);
    let encoded = verifying_key.to_encoded_point(true);
    let pubkey_bytes = encoded.as_bytes();

    // (note that ephemeralECPubkey is known both to the User and the Notary)
    let signed_tls = SignedTLS::new(TIME, eph_ec, commitment_to_tls);
    let signed = Signed::new(signed_tls.clone(), label_seed, merkle_root);

    let signature = signing_key.sign(&bincode::serialize(&signed).unwrap());
    let sig_der = signature.to_der();
    let signature = sig_der.as_bytes();

    // the Notary reveals `label_seed` and also sends the `signature` and `time`.
    // After that the User creates a doc for the Verifier:
    // (The User creates `signed_tls` just like the Notary did above)
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

    // The User converts the doc into an unchecked Type and passes it to the Verifier
    let doc_unchecked: VerifierDocUnchecked = doc.into();

    // The Verifier verifies the doc:

    // Initially the Verifier may store the Notary's pubkey as bytes. Converts it into
    // PubKey type
    let trusted_pubkey = PubKey::from_bytes(KeyType::P256, pubkey_bytes);

    let verifier = VerifierCore::new(doc_unchecked, Some(trusted_pubkey)).unwrap();

    verifier.verify("tlsnotary.org".to_string()).unwrap();
}
