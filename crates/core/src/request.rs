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

#[cfg(test)]
mod test {
    use super::*;

    use crate::{
        attestation::{Attestation, AttestationConfig},
        connection::{HandshakeData, HandshakeDataV1_2, ServerCertOpening, TranscriptLength},
        fixtures::{encoder_seed, encoding_provider, ConnectionFixture},
        hash::{Blake3, Hash, HashAlgId},
        signing::SignatureAlgId,
        transcript::{encoding::EncodingTree, Transcript, TranscriptCommitConfigBuilder},
        CryptoProvider,
    };

    use tlsn_data_fixtures::http::{request::GET_WITH_HEADER, response::OK_JSON};

    fn attestation(payload: (Request, ConnectionFixture)) -> Attestation {
        let (request, connection) = payload;

        let ConnectionFixture {
            connection_info,
            server_cert_data,
            ..
        } = connection;

        let HandshakeData::V1_2(HandshakeDataV1_2 {
            server_ephemeral_key,
            ..
        }) = server_cert_data.handshake.clone();

        let mut provider = CryptoProvider::default();
        provider.signer.set_secp256k1(&[42u8; 32]).unwrap();

        let attestation_config = AttestationConfig::builder()
            .supported_signature_algs([SignatureAlgId::SECP256K1])
            .build()
            .unwrap();

        let mut attestation_builder = Attestation::builder(&attestation_config)
            .accept_request(request.clone())
            .unwrap();

        attestation_builder
            .connection_info(connection_info.clone())
            .server_ephemeral_key(server_ephemeral_key)
            .encoding_seed(encoder_seed().to_vec());

        attestation_builder.build(&provider).unwrap()
    }

    fn request_and_connection() -> (Request, ConnectionFixture) {
        let provider = CryptoProvider::default();

        let transcript = Transcript::new(GET_WITH_HEADER, OK_JSON);
        let (sent_len, recv_len) = transcript.len();
        // Plaintext encodings which the Prover obtained from GC evaluation
        let encodings_provider = encoding_provider(GET_WITH_HEADER, OK_JSON);

        // At the end of the TLS connection the Prover holds the:
        let ConnectionFixture {
            server_name,
            server_cert_data,
            ..
        } = ConnectionFixture::tlsnotary(transcript.length());

        // Prover specifies the ranges it wants to commit to.
        let mut transcript_commitment_builder = TranscriptCommitConfigBuilder::new(&transcript);
        transcript_commitment_builder
            .commit_sent(&(0..sent_len))
            .unwrap()
            .commit_recv(&(0..recv_len))
            .unwrap();

        let transcripts_commitment_config = transcript_commitment_builder.build().unwrap();

        // Prover constructs encoding tree.
        let encoding_tree = EncodingTree::new(
            &Blake3::default(),
            transcripts_commitment_config.iter_encoding(),
            &encodings_provider,
            &transcript.length(),
        )
        .unwrap();

        let request_config = RequestConfig::default();
        let mut request_builder = Request::builder(&request_config);

        request_builder
            .server_name(server_name.clone())
            .server_cert_data(server_cert_data)
            .transcript(transcript.clone())
            .encoding_tree(encoding_tree);
        let (request, _) = request_builder.build(&provider).unwrap();

        (request, ConnectionFixture::tlsnotary(transcript.length()))
    }

    #[test]
    fn test_success() {
        let (request, connection) = request_and_connection();

        let attestation = attestation((request.clone(), connection));

        assert!(request.validate(&attestation).is_ok())
    }

    #[test]
    fn test_wrong_signature_alg() {
        let (mut request, connection) = request_and_connection();

        let attestation = attestation((request.clone(), connection));

        request.signature_alg = SignatureAlgId::SECP256R1;

        let res = request.validate(&attestation);
        assert!(res.is_err());
    }

    #[test]
    fn test_wrong_hash_alg() {
        let (mut request, connection) = request_and_connection();

        let attestation = attestation((request.clone(), connection));

        request.hash_alg = HashAlgId::SHA256;

        let res = request.validate(&attestation);
        assert!(res.is_err())
    }

    #[test]
    fn test_wrong_server_commitment() {
        let (mut request, connection) = request_and_connection();

        let attestation = attestation((request.clone(), connection));

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

        let res = request.validate(&attestation);
        assert!(res.is_err())
    }

    #[test]
    fn test_wrong_encoding_commitment_root() {
        let (mut request, connection) = request_and_connection();

        let attestation = attestation((request.clone(), connection));

        request.encoding_commitment_root = Some(TypedHash {
            alg: HashAlgId::BLAKE3,
            value: Hash::default(),
        });

        let res = request.validate(&attestation);
        assert!(res.is_err())
    }
}
