mod commitment;
mod error;
mod signed;
mod tls_doc;
mod verifier_doc;
mod verify_signature;
mod webpki_utils;

use verifier_doc::{Signature, VerifierDoc};

use crate::signed::Signed;
use error::Error;

type HashCommitment = [u8; 32];

struct VerifierCore {
    /// notarization doc which needs to be verified
    doc: VerifierDoc,
    /// trusted notary's pubkey. If this Verifier is also the Notary then no pubkey needs
    /// to be provided, the signature on the [crate::main_doc::MainDoc] will not be checked.
    trusted_pubkey: Option<Pubkey>,
}

/// Verifies the core aspects of the notarization session: the Notary signature, the TLS
/// authenticity and the correctness of commitments and zk proofs.
///
/// After the verification completes, the application level (e.g. HTTP) parser can start
/// parsing the openings in [VerifierDoc::commitment_openings]
impl VerifierCore {
    pub fn new(doc: VerifierDoc, trusted_pubkey: Option<Pubkey>) -> Self {
        Self {
            doc,
            trusted_pubkey,
        }
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

        // perform sanity checks on the doc
        self.doc.check()?;

        // verify all other aspects of notarization
        self.doc.verify(dns_name)?;

        Ok(())
    }

    // verify Notary's sig on the notarization doc
    fn verify_doc_signature(
        &self,
        pubkey: &Pubkey,
        sig: &Signature,
        msg: &Signed,
    ) -> Result<bool, Error> {
        if pubkey.typ != sig.typ {
            return Err(Error::VerificationError);
        }
        let result = match sig.typ {
            Curve::p256 => {
                verify_signature::verify_sig_p256(&msg.serialize(), &pubkey.pubkey, &sig.signature)
            }
            _ => false,
        };
        if !result {
            return Err(Error::VerificationError);
        } else {
            Ok(true)
        }
    }

    // extracts the necessary data from the VerifierDoc into a Signed
    // struct and returns it
    fn signed_data(&self) -> Signed {
        //let doc = &self.doc.clone();
        (&self.doc).into()
    }
}

#[derive(Clone)]
struct Pubkey {
    typ: Curve,
    pubkey: Vec<u8>,
}

#[derive(PartialEq, Clone)]
pub enum Curve {
    // different curves
    secp256k1,
    p256,
    bn254,
    bls12381,
    pallas,
}

#[derive(Clone)]
/// A PRG seeds from which to generate Notary's circuits' input labels for one
/// direction. We will use 2 separate seeds: one to generate the labels for all
/// plaintext which was sent and another seed to generate the labels for all plaintext
/// which was received
pub struct LabelSeed {
    typ: SeedType,
    value: Vec<u8>,
}

#[derive(Clone)]
enum SeedType {
    chacha12,
    chacha20,
    fixed_key_aes,
}
