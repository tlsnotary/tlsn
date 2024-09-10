//! Attestation requests.
//!
//! After the TLS connection, a Prover can request an attestation from the Notary which contains
//! various information about the connection. During this process the Prover has the opportunity
//! to configure certain aspects of the attestation, such as which signature algorithm the Notary
//! should use to sign the attestation. Or which hash algorithm the Notary should use to merkelize
//! the fields.
//!
//! A [`Request`] can be created using a [`RequestBuilder`]. The builder will take both configuration
//! via a [`RequestConfig`] as well as the Prover's secret data. The [`Secrets`](crate::Secrets) are of
//! course not shared with the Notary but are used to create commitments which are included in the attestation.

mod builder;
mod config;

use serde::{Deserialize, Serialize};

use crate::{
    attestation::Attestation,
    connection::ServerCertCommitment,
    hash::{HashAlgId, TypedHash},
    signing::SignatureAlgId,
};

pub use builder::{RequestBuilder, RequestBuilderError};
pub use config::{RequestConfig, RequestConfigBuilder, RequestConfigBuilderError};

/// Attestation request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub(crate) signature_alg: SignatureAlgId,
    pub(crate) hash_alg: HashAlgId,
    pub(crate) server_cert_commitment: ServerCertCommitment,
    pub(crate) encoding_commitment_root: Option<TypedHash>,
}

impl Request {
    /// Returns a new request builder.
    pub fn builder(config: &RequestConfig) -> RequestBuilder {
        RequestBuilder::new(config)
    }

    /// Validates the content of the attestation against this request.
    pub fn validate(&self, attestation: &Attestation) -> Result<(), InconsistentAttestation> {
        if attestation.signature.alg != self.signature_alg {
            return Err(InconsistentAttestation(format!(
                "signature algorithm: expected {:?}, got {:?}",
                self.signature_alg, attestation.signature.alg
            )));
        }

        if attestation.header.root.alg != self.hash_alg {
            return Err(InconsistentAttestation(format!(
                "hash algorithm: expected {:?}, got {:?}",
                self.hash_alg, attestation.header.root.alg
            )));
        }

        if attestation.body.cert_commitment() != &self.server_cert_commitment {
            return Err(InconsistentAttestation(
                "server certificate commitment does not match".to_string(),
            ));
        }

        if let Some(encoding_commitment_root) = &self.encoding_commitment_root {
            let Some(encoding_commitment) = attestation.body.encoding_commitment() else {
                return Err(InconsistentAttestation(
                    "encoding commitment is missing".to_string(),
                ));
            };

            if &encoding_commitment.root != encoding_commitment_root {
                return Err(InconsistentAttestation(
                    "encoding commitment root does not match".to_string(),
                ));
            }
        }

        Ok(())
    }
}

/// Error for [`Request::validate`].
#[derive(Debug, thiserror::Error)]
#[error("inconsistent attestation: {0}")]
pub struct InconsistentAttestation(String);
