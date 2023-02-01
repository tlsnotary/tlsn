mod checks;
pub mod commitment;
pub mod doc;
mod error;
mod label_encoder;
pub mod pubkey;
pub mod signed;
pub mod tls_handshake;
mod utils;
mod webpki_utils;

use crate::{doc::ValidatedDoc, signed::Signed};
use doc::{UncheckedDoc, VerifiedDoc};
use error::Error;
use pubkey::PubKey;

pub type HashCommitment = [u8; 32];

/// A PRG seeds from which to generate garbled circuit active labels, see
/// [crate::commitment::CommitmentType::labels_blake3]
pub type LabelSeed = [u8; 32];

/// Verifier of the notarization document
///
/// Once the verification succeeds, an application level (e.g. HTTP, JSON) parser can
/// parse `commitment_openings` in `doc`
pub struct Verifier {}

impl Verifier {
    /// Creates a new Verifier
    pub fn new() -> Self {
        Self {}
    }

    /// Verifies that the notarization document resulted from notarizing data from a TLS server with the
    /// DNS name `dns_name`. Also verifies the Notary's signature (if any).
    ///
    /// IMPORTANT:
    /// if the notarized application data is HTTP, the checks below will not be sufficient. You must also
    /// check on the HTTP parser's level against domain fronting.
    ///
    /// * unchecked_doc - The notarization document to be validated and verified
    /// * trusted_pubkey - A trusted Notary's pubkey (if this Verifier acted as the Notary then no
    ///                    pubkey needs to be provided)
    /// * dns_name - A DNS name. Must be exactly as it appears in the server's TLS certificate.
    pub fn verify(
        &self,
        unchecked_doc: UncheckedDoc,
        trusted_pubkey: Option<PubKey>,
        dns_name: String,
    ) -> Result<VerifiedDoc, Error> {
        // validate the document
        let doc = ValidatedDoc::from_unchecked(unchecked_doc)?;

        // verify Notary's signature, if any
        match (doc.signature(), &trusted_pubkey) {
            (Some(sig), Some(pubkey)) => {
                self.verify_doc_signature(pubkey, sig, self.signed_data(&doc))?;
            }
            // no pubkey and no signature, do nothing
            (None, None) => (),
            // either pubkey or signature is missing
            _ => {
                return Err(Error::NoPubkeyOrSignature);
            }
        }

        // verify the document
        doc.verify(dns_name)?;

        Ok(VerifiedDoc::from_validated(doc))
    }

    /// Verifies Notary's signature on that part of the document which was signed
    fn verify_doc_signature(&self, pubkey: &PubKey, sig: &[u8], msg: Signed) -> Result<(), Error> {
        let msg = msg.serialize()?;
        pubkey.verify_signature(&msg, sig)
    }

    /// Extracts the necessary fields from the [VerifiedDoc] into a [Signed]
    /// struct and returns it
    fn signed_data(&self, doc: &ValidatedDoc) -> Signed {
        doc.into()
    }
}
