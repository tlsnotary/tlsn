mod checks;
pub mod commitment;
pub mod doc;
mod error;
mod label_encoder;
pub mod pubkey;
pub mod signed;
pub mod tls_handshake;
mod utils;
pub mod verified_transcript;
mod webpki_utils;

use crate::{doc::ValidatedDoc, signed::Signed, verified_transcript::VerifiedTranscript};
use doc::{UncheckedDoc, VerifiedDoc};
use error::Error;
use pubkey::PubKey;

pub type HashCommitment = [u8; 32];

/// A PRG seeds from which to generate garbled circuit active labels, see
/// [crate::commitment::CommitmentType::labels_blake3]
pub type LabelSeed = [u8; 32];

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
    /// * unchecked_doc - The notarization document to be validated and verified
    /// * dns_name - A DNS name. Must be exactly as it appears in the server's TLS certificate.
    /// * signed - If this Verifier acted as the Notary, he provides his [Signed] struct
    /// * trusted_pubkey - A trusted Notary's pubkey (if this Verifier acted as the Notary then no
    ///                    pubkey needs to be provided)
    pub fn verify(
        &self,
        unchecked_doc: UncheckedDoc,
        dns_name: &str,
        trusted_pubkey: Option<PubKey>,
        signed: Option<Signed>,
    ) -> Result<VerifiedTranscript, Error> {
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
