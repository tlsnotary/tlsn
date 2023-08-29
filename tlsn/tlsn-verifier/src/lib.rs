use mpz_core::{commit::CommitmentError, serialize::CanonicalSerialize};
use p256::ecdsa::{signature::Verifier as SignatureVerifier, VerifyingKey};
use std::time::{Duration, UNIX_EPOCH};
use thiserror::Error;
use tls_core::{
    anchors::{OwnedTrustAnchor, RootCertStore},
    dns::ServerName,
    verify::{ServerCertVerifier, WebPkiVerifier},
    Error as TlsCoreError,
};
use tlsn_core::{
    signature::Signature, substrings::proof::SubstringsProof, Error as TlsnCoreError, SessionProof,
};

pub struct Verifier {
    server_name: ServerName,
    notary_pubkey: Option<VerifyingKey>,
    session_proof: SessionProof,
}

impl Verifier {
    pub fn new(
        server_name: impl TryInto<ServerName>,
        notary_pubkey: Option<VerifyingKey>,
        session_proof: SessionProof,
    ) -> Result<Self, VerifierError> {
        let server_name = server_name
            .try_into()
            .map_err(|_| VerifierError::Servername)?;

        let verifier = Verifier {
            server_name,
            notary_pubkey,
            session_proof,
        };

        verifier.verify()?;

        Ok(verifier)
    }

    pub fn set_new_session_proof(
        &mut self,
        session_proof: SessionProof,
    ) -> Result<(), VerifierError> {
        self.session_proof = session_proof;
        self.verify()
    }

    pub fn verify_substring_proof(
        &self,
        proof: SubstringsProof,
    ) -> Result<(String, String), VerifierError> {
        let header = self.session_proof.header();
        let (sent_slices, received_slices) = proof
            .verify(header)
            .map_err(VerifierError::InvalidSubstringProof)?;

        let mut sent_transcript = vec![b'X'; header.sent_len() as usize];
        let mut received_transcript = vec![b'X'; header.recv_len() as usize];

        for slice in sent_slices {
            sent_transcript[slice.range().start as usize..slice.range().end as usize]
                .copy_from_slice(slice.data())
        }

        for slice in received_slices {
            received_transcript[slice.range().start as usize..slice.range().end as usize]
                .copy_from_slice(slice.data())
        }

        Ok((
            String::from_utf8(sent_transcript).map_err(VerifierError::Utf8Error)?,
            String::from_utf8(received_transcript).map_err(VerifierError::Utf8Error)?,
        ))
    }

    fn verify(&self) -> Result<(), VerifierError> {
        if let Some(notary_pk) = self.notary_pubkey {
            self.verify_notary_signature(notary_pk)?;
        }

        self.verify_handshake_data_decommitment()?;
        self.verify_cert_chain()?;

        Ok(())
    }

    fn verify_notary_signature(&self, notary_pubkey: VerifyingKey) -> Result<(), VerifierError> {
        match self.session_proof.signature {
            Some(Signature::P256(sig)) => notary_pubkey
                .verify(&self.session_proof.header.to_bytes(), &sig)
                .map_err(VerifierError::InvalidNotarySignature),
            None => Err(VerifierError::MissingNotarySignature),
            Some(_) => unreachable!(),
        }
    }

    fn verify_handshake_data_decommitment(&self) -> Result<(), VerifierError> {
        let hs_commitment = self
            .session_proof
            .header()
            .handshake_summary()
            .handshake_commitment();
        let hs_decommitment = self.session_proof.handshake_data_decommitment();

        hs_decommitment
            .verify(hs_commitment)
            .map_err(VerifierError::CommitmentError)
    }

    fn verify_cert_chain(&self) -> Result<(), VerifierError> {
        let cert_verifier = &default_cert_verifier();
        let header = self.session_proof.header();
        let server_name = &self.server_name;

        let hs_data = self.session_proof.handshake_data_decommitment().data();
        let hs_time = header.handshake_summary().time();

        hs_data
            .verify(
                cert_verifier,
                UNIX_EPOCH + Duration::from_secs(hs_time),
                server_name,
            )
            .map_err(VerifierError::InvalidCertChain)
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

#[derive(Debug, Error)]
pub enum VerifierError {
    #[error("Invalid server name")]
    Servername,
    #[error("Missing notary signature")]
    MissingNotarySignature,
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
}
