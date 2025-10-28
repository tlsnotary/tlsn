//! Attestation requests.
//!
//! After the TLS connection, a Prover can request an attestation from the
//! Notary which contains various information about the connection. During this
//! process the Prover has the opportunity to configure certain aspects of the
//! attestation, such as which signature algorithm the Notary should use to sign
//! the attestation. Or which hash algorithm the Notary should use to merkelize
//! the fields.
//!
//! A [`Request`] can be created using a [`RequestBuilder`]. The builder will
//! take both configuration via a [`RequestConfig`] as well as the Prover's
//! secret data. The [`Secrets`](crate::Secrets) are of course not shared with
//! the Notary but are used to create commitments which are included in the
//! attestation.

mod builder;
mod config;

use serde::{Deserialize, Serialize};

use tlsn_core::hash::HashAlgId;

use crate::{
    Attestation, Extension,
    connection::ServerCertCommitment,
    serialize::CanonicalSerialize,
    signing::{SignatureAlgId, SignatureVerifierProvider},
};

pub use builder::{RequestBuilder, RequestBuilderError};
pub use config::{RequestConfig, RequestConfigBuilder, RequestConfigBuilderError};

/// Attestation request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub(crate) signature_alg: SignatureAlgId,
    pub(crate) hash_alg: HashAlgId,
    pub(crate) server_cert_commitment: ServerCertCommitment,
    pub(crate) extensions: Vec<Extension>,
}

impl Request {
    /// Returns a new request builder.
    pub fn builder(config: &RequestConfig) -> RequestBuilder<'_> {
        RequestBuilder::new(config)
    }

    /// Validates the content of the attestation against this request.
    pub fn validate(
        &self,
        attestation: &Attestation,
        provider: &SignatureVerifierProvider,
    ) -> Result<(), AttestationValidationError> {
        if attestation.signature.alg != self.signature_alg {
            return Err(AttestationValidationError::inconsistent(format!(
                "signature algorithm: expected {:?}, got {:?}",
                self.signature_alg, attestation.signature.alg
            )));
        }

        if attestation.header.root.alg != self.hash_alg {
            return Err(AttestationValidationError::inconsistent(format!(
                "hash algorithm: expected {:?}, got {:?}",
                self.hash_alg, attestation.header.root.alg
            )));
        }

        if attestation.body.cert_commitment() != &self.server_cert_commitment {
            return Err(AttestationValidationError::inconsistent(
                "server certificate commitment does not match",
            ));
        }

        // TODO: improve the O(M*N) complexity of this check.
        for extension in &self.extensions {
            if !attestation.body.extensions().any(|e| e == extension) {
                return Err(AttestationValidationError::inconsistent(
                    "extension is missing from the attestation",
                ));
            }
        }

        let verifier = provider.get(&attestation.signature.alg).map_err(|_| {
            AttestationValidationError::provider(format!(
                "provider not configured for signature algorithm id {:?}",
                attestation.signature.alg,
            ))
        })?;

        verifier
            .verify(
                &attestation.body.verifying_key.data,
                &CanonicalSerialize::serialize(&attestation.header),
                &attestation.signature.data,
            )
            .map_err(|_| {
                AttestationValidationError::inconsistent("failed to verify the signature")
            })?;

        Ok(())
    }
}

/// Error for [`Request::validate`].
#[derive(Debug, thiserror::Error)]
#[error("attestation validation error: {kind}: {message}")]
pub struct AttestationValidationError {
    kind: ErrorKind,
    message: String,
}

impl AttestationValidationError {
    fn inconsistent(msg: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::Inconsistent,
            message: msg.into(),
        }
    }

    fn provider(msg: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::Provider,
            message: msg.into(),
        }
    }
}

#[derive(Debug)]
enum ErrorKind {
    Inconsistent,
    Provider,
}

impl std::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorKind::Inconsistent => write!(f, "inconsistent"),
            ErrorKind::Provider => write!(f, "provider"),
        }
    }
}

#[cfg(test)]
mod test {
    use tlsn_core::{
        connection::TranscriptLength,
        fixtures::{ConnectionFixture, encoding_provider},
        hash::{Blake3, HashAlgId},
        transcript::Transcript,
    };
    use tlsn_data_fixtures::http::{request::GET_WITH_HEADER, response::OK_JSON};

    use crate::{
        CryptoProvider,
        connection::ServerCertOpening,
        fixtures::{RequestFixture, attestation_fixture, custom_provider_fixture, request_fixture},
        request::{AttestationValidationError, ErrorKind},
        signing::{SignatureAlgId, SignatureVerifierProvider},
    };

    #[test]
    fn test_success() {
        let transcript = Transcript::new(GET_WITH_HEADER, OK_JSON);
        let connection = ConnectionFixture::tlsnotary(transcript.length());

        let RequestFixture { request, .. } = request_fixture(
            transcript,
            encoding_provider(GET_WITH_HEADER, OK_JSON),
            connection.clone(),
            Blake3::default(),
            Vec::new(),
        );

        let attestation =
            attestation_fixture(request.clone(), connection, SignatureAlgId::SECP256K1, &[]);

        let provider = SignatureVerifierProvider::default();

        assert!(request.validate(&attestation, &provider).is_ok())
    }

    #[test]
    fn test_wrong_signature_alg() {
        let transcript = Transcript::new(GET_WITH_HEADER, OK_JSON);
        let connection = ConnectionFixture::tlsnotary(transcript.length());

        let RequestFixture { mut request, .. } = request_fixture(
            transcript,
            encoding_provider(GET_WITH_HEADER, OK_JSON),
            connection.clone(),
            Blake3::default(),
            Vec::new(),
        );

        let attestation =
            attestation_fixture(request.clone(), connection, SignatureAlgId::SECP256K1, &[]);

        request.signature_alg = SignatureAlgId::SECP256R1;

        let provider = SignatureVerifierProvider::default();

        let res = request.validate(&attestation, &provider);
        assert!(res.is_err());
    }

    #[test]
    fn test_wrong_hash_alg() {
        let transcript = Transcript::new(GET_WITH_HEADER, OK_JSON);
        let connection = ConnectionFixture::tlsnotary(transcript.length());

        let RequestFixture { mut request, .. } = request_fixture(
            transcript,
            encoding_provider(GET_WITH_HEADER, OK_JSON),
            connection.clone(),
            Blake3::default(),
            Vec::new(),
        );

        let attestation =
            attestation_fixture(request.clone(), connection, SignatureAlgId::SECP256K1, &[]);

        request.hash_alg = HashAlgId::SHA256;

        let provider = SignatureVerifierProvider::default();

        let res = request.validate(&attestation, &provider);
        assert!(res.is_err())
    }

    #[test]
    fn test_wrong_server_commitment() {
        let transcript = Transcript::new(GET_WITH_HEADER, OK_JSON);
        let connection = ConnectionFixture::tlsnotary(transcript.length());

        let RequestFixture { mut request, .. } = request_fixture(
            transcript,
            encoding_provider(GET_WITH_HEADER, OK_JSON),
            connection.clone(),
            Blake3::default(),
            Vec::new(),
        );

        let attestation =
            attestation_fixture(request.clone(), connection, SignatureAlgId::SECP256K1, &[]);

        let ConnectionFixture {
            server_cert_data, ..
        } = ConnectionFixture::appliedzkp(TranscriptLength {
            sent: 100,
            received: 100,
        });
        let opening = ServerCertOpening::new(server_cert_data);

        let crypto_provider = CryptoProvider::default();
        request.server_cert_commitment =
            opening.commit(crypto_provider.hash.get(&HashAlgId::BLAKE3).unwrap());

        let provider = SignatureVerifierProvider::default();

        let res = request.validate(&attestation, &provider);
        assert!(res.is_err())
    }

    #[test]
    fn test_wrong_sig() {
        let transcript = Transcript::new(GET_WITH_HEADER, OK_JSON);
        let connection = ConnectionFixture::tlsnotary(transcript.length());

        let RequestFixture { request, .. } = request_fixture(
            transcript,
            encoding_provider(GET_WITH_HEADER, OK_JSON),
            connection.clone(),
            Blake3::default(),
            Vec::new(),
        );

        let mut attestation =
            attestation_fixture(request.clone(), connection, SignatureAlgId::SECP256K1, &[]);

        // Corrupt the signature.
        attestation.signature.data[1] = attestation.signature.data[1].wrapping_add(1);

        let provider = SignatureVerifierProvider::default();

        assert!(request.validate(&attestation, &provider).is_err())
    }

    #[test]
    fn test_wrong_provider() {
        let transcript = Transcript::new(GET_WITH_HEADER, OK_JSON);
        let connection = ConnectionFixture::tlsnotary(transcript.length());

        let RequestFixture { request, .. } = request_fixture(
            transcript,
            encoding_provider(GET_WITH_HEADER, OK_JSON),
            connection.clone(),
            Blake3::default(),
            Vec::new(),
        );

        let attestation =
            attestation_fixture(request.clone(), connection, SignatureAlgId::SECP256K1, &[]);

        let provider = custom_provider_fixture();

        assert!(matches!(
            request.validate(&attestation, &provider.signature),
            Err(AttestationValidationError {
                kind: ErrorKind::Provider,
                ..
            })
        ))
    }
}
