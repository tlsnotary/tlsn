//! The verifier library
//!
//! The [Verifier] is used to verify [session proofs](SessionProof) and [substrings proofs](SubstringsProof) for a given domain.
//! When doing a notarization with the TLSNotary protocol, the output will be a [notarized session](tlsn_core::NotarizedSession),
//! which contains a session proof. This session proof can be used by the verifier to verify parts
//! of a notarized session's traffic data which he accepts in the form of substring proofs.
//!
//! So the usual workflow for a verifier is as follows:
//! 1. Create a [new verifier](Verifier::new).
//! 2. [Set the session proof](Verifier::set_session_proof) which should be used for substring
//!    verification. This will also verify the session proof itself.
//! 3. [Verify substring proofs](Verifier::verify_substring_proof).

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

use mpz_core::{commit::CommitmentError, serialize::CanonicalSerialize};
use p256::ecdsa::{signature::Verifier as SignatureVerifier, VerifyingKey};
use std::{
    ops::Range,
    time::{Duration, UNIX_EPOCH},
};
use thiserror::Error;
use tls_core::{
    anchors::{OwnedTrustAnchor, RootCertStore},
    dns::ServerName,
    verify::{ServerCertVerifier, WebPkiVerifier},
    Error as TlsCoreError,
};
use tlsn_core::{
    signature::Signature, substrings::proof::SubstringsProof, Direction, Error as TlsnCoreError,
    SessionProof, Transcript,
};
use utils::invert_range::invert_range;

mod assert;
use assert::VerifiedTranscript;

/// Valid characters for redacted parts in transcripts
pub const VALID_REDACTMENT_CHARS: &[u8] = b"x";

/// The Verifier
///
/// The Verifier is used to verify session proofs and substrings proofs for some domain.
pub struct Verifier {
    server_name: ServerName,
    notary_pubkey: Option<VerifyingKey>,
    session_proof: Option<SessionProof>,
}

impl Verifier {
    /// Create a new verifier
    ///
    /// Creates a new verifier for the given server name and notary public key used for
    /// verification.
    pub fn new(
        server_name: impl TryInto<ServerName>,
        notary_pubkey: VerifyingKey,
    ) -> Result<Self, VerifierError> {
        Self::new_internal(server_name, Some(notary_pubkey), None)
    }

    /// Create a new verifier without providing a notary public key for verification
    ///
    /// # Attention
    /// This means that the verifier will **NOT CHECK** the notary signature for session proofs so
    /// that they can easily be forged. This mode is useful if you also run a notary server
    /// yourself and **ONLY** pass session proofs created by this notary server to the verifier.
    pub fn new_without_pubkey(
        server_name: impl TryInto<ServerName>,
    ) -> Result<Self, VerifierError> {
        Self::new_internal(server_name, None, None)
    }

    /// Set the session proof
    ///
    /// Sets a new session proof and verifies it.
    pub fn set_session_proof(&mut self, session_proof: SessionProof) -> Result<(), VerifierError> {
        self.session_proof = Some(session_proof);
        let verify_result = self.verify_session_proof();

        if verify_result.is_err() {
            self.session_proof = None;
        }
        verify_result
    }

    /// Checks that the given `transcript` and substring `proof` are valid
    ///
    /// This function checks that
    /// * the substring proof is valid against the session proof
    /// * the length of the redacted transcript is correct
    /// * the redacted transcript matches the decommitments
    /// * the redacted transcript only contains valid characters
    pub fn verify_transcript(
        &self,
        proof: SubstringsProof,
        transcript: Transcript,
        direction: Direction,
    ) -> Result<VerifiedTranscript, VerifierError> {
        let header = self
            .session_proof
            .as_ref()
            .ok_or(VerifierError::MissingSessionProof)?
            .header();

        // Verify the session proof against the session header
        let (verified_sent, verified_received) = proof
            .verify(header)
            .map_err(VerifierError::InvalidSubstringProof)?;

        let (expected_len, decommitment_slices) = match direction {
            Direction::Sent => (header.sent_len() as usize, verified_sent),
            Direction::Received => (header.recv_len() as usize, verified_received),
        };

        // Check the redacted transcript lengths
        if expected_len != transcript.data().len() {
            return Err(VerifierError::InvalidRedactedTranscript);
        }

        // Check that the transcript matches the decommitments
        if decommitment_slices.iter().any(|el| {
            *el.data() != transcript.data()[el.range().start as usize..el.range().end as usize]
        }) {
            return Err(VerifierError::InvalidRedactedTranscript);
        }

        // Check that redacted transcript only uses valid characters
        let redacted_ranges = invert_range(
            &(0..transcript.data().len()),
            decommitment_slices
                .iter()
                .map(|el| el.range().start as usize..el.range().end as usize)
                .collect::<Vec<Range<usize>>>()
                .as_slice(),
        )?;

        if redacted_ranges.into_iter().any(|range| {
            transcript.data()[range]
                .iter()
                .any(|el| !VALID_REDACTMENT_CHARS.contains(el))
        }) {
            return Err(VerifierError::InvalidRedactedTranscript);
        }

        let verified_transcript = VerifiedTranscript {
            data: transcript.data().to_vec(),
        };

        Ok(verified_transcript)
    }

    fn verify_session_proof(&self) -> Result<(), VerifierError> {
        if let Some(notary_pk) = self.notary_pubkey {
            self.verify_notary_signature(notary_pk)?;
        }

        self.verify_handshake_data_decommitment()?;
        self.verify_cert_chain()?;

        Ok(())
    }

    fn verify_notary_signature(&self, notary_pubkey: VerifyingKey) -> Result<(), VerifierError> {
        let session_proof = self
            .session_proof
            .as_ref()
            .ok_or(VerifierError::MissingSessionProof)?;

        match session_proof.signature {
            Some(Signature::P256(sig)) => notary_pubkey
                .verify(&session_proof.header.to_bytes(), &sig)
                .map_err(VerifierError::InvalidNotarySignature),
            None => Err(VerifierError::MissingNotarySignature),
            Some(_) => unreachable!(),
        }
    }

    fn verify_handshake_data_decommitment(&self) -> Result<(), VerifierError> {
        let session_proof = self
            .session_proof
            .as_ref()
            .ok_or(VerifierError::MissingSessionProof)?;

        let hs_commitment = session_proof
            .header()
            .handshake_summary()
            .handshake_commitment();
        let hs_decommitment = session_proof.handshake_data_decommitment();

        hs_decommitment
            .verify(hs_commitment)
            .map_err(VerifierError::CommitmentError)
    }

    fn verify_cert_chain(&self) -> Result<(), VerifierError> {
        let session_proof = self
            .session_proof
            .as_ref()
            .ok_or(VerifierError::MissingSessionProof)?;

        let cert_verifier = &default_cert_verifier();
        let header = session_proof.header();
        let server_name = &self.server_name;

        let hs_data = session_proof.handshake_data_decommitment().data();
        let hs_time = header.handshake_summary().time();

        hs_data
            .verify(
                cert_verifier,
                UNIX_EPOCH + Duration::from_secs(hs_time),
                server_name,
            )
            .map_err(VerifierError::InvalidCertChain)
    }

    fn new_internal(
        server_name: impl TryInto<ServerName>,
        notary_pubkey: Option<VerifyingKey>,
        session_proof: Option<SessionProof>,
    ) -> Result<Self, VerifierError> {
        let server_name = server_name
            .try_into()
            .map_err(|_| VerifierError::Servername)?;

        let verifier = Verifier {
            server_name,
            notary_pubkey,
            session_proof,
        };

        Ok(verifier)
    }
}

fn default_cert_verifier() -> impl ServerCertVerifier {
    let mut root_store = RootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    WebPkiVerifier::new(root_store, None)
}

/// Errors that can occur during verification
#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum VerifierError {
    #[error("Invalid server name")]
    Servername,
    #[error("Missing notary signature")]
    MissingNotarySignature,
    #[error("Missing session proof")]
    MissingSessionProof,
    #[error("The redacted transcript does not match the decommitments")]
    InvalidRedactedTranscript,
    #[error(transparent)]
    InvalidNotarySignature(#[from] p256::ecdsa::Error),
    #[error(transparent)]
    InvalidCertChain(#[from] TlsCoreError),
    #[error(transparent)]
    InvalidSubstringProof(#[from] TlsnCoreError),
    #[error(transparent)]
    Utf8Error(#[from] std::string::FromUtf8Error),
    #[error(transparent)]
    CommitmentError(#[from] CommitmentError),
    #[error(transparent)]
    Range(#[from] utils::invert_range::RangeError),
}