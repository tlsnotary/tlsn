use std::error::Error;

use rand::{thread_rng, Rng};

use crate::{
    attestation::{
        Attestation, AttestationConfig, Body, EncodingCommitment, FieldId, FieldKind, Header,
        ServerCertCommitment, VERSION,
    },
    connection::{ConnectionInfo, ServerEphemKey},
    hash::{HashAlgId, TypedHash},
    request::Request,
    serialize::CanonicalSerialize,
    signing::SignatureAlgId,
    CryptoProvider,
};

/// Attestation builder state for accepting a request.
pub struct Accept {}

pub struct Sign {
    signature_alg: SignatureAlgId,
    hash_alg: HashAlgId,
    connection_info: Option<ConnectionInfo>,
    server_ephemeral_key: Option<ServerEphemKey>,
    cert_commitment: ServerCertCommitment,
    encoding_commitment_root: Option<TypedHash>,
    encoding_seed: Option<Vec<u8>>,
}

/// An attestation builder.
pub struct AttestationBuilder<'a, T = Accept> {
    config: &'a AttestationConfig,
    state: T,
}

impl<'a> AttestationBuilder<'a, Accept> {
    /// Creates a new attestation builder.
    pub fn new(config: &'a AttestationConfig) -> Self {
        Self {
            config,
            state: Accept {},
        }
    }

    /// Accepts the attestation request.
    pub fn accept_request(
        self,
        request: Request,
    ) -> Result<AttestationBuilder<'a, Sign>, AttestationBuilderError> {
        let config = self.config;

        let Request {
            signature_alg,
            hash_alg,
            server_cert_commitment: cert_commitment,
            encoding_commitment_root,
        } = request;

        if !config.supported_signature_algs().contains(&signature_alg) {
            return Err(AttestationBuilderError::new(
                ErrorKind::Request,
                format!("unsupported signature algorithm: {signature_alg}"),
            ));
        }

        if !config.supported_hash_algs().contains(&hash_alg) {
            return Err(AttestationBuilderError::new(
                ErrorKind::Request,
                format!("unsupported hash algorithm: {hash_alg}"),
            ));
        }

        if encoding_commitment_root.is_some()
            && !config
                .supported_fields()
                .contains(&FieldKind::EncodingCommitment)
        {
            return Err(AttestationBuilderError::new(
                ErrorKind::Request,
                "encoding commitment is not supported",
            ));
        }

        Ok(AttestationBuilder {
            config: self.config,
            state: Sign {
                signature_alg,
                hash_alg,
                connection_info: None,
                server_ephemeral_key: None,
                cert_commitment,
                encoding_commitment_root,
                encoding_seed: None,
            },
        })
    }
}

impl AttestationBuilder<'_, Sign> {
    /// Sets the connection information.
    pub fn connection_info(&mut self, connection_info: ConnectionInfo) -> &mut Self {
        self.state.connection_info = Some(connection_info);
        self
    }

    /// Sets the server ephemeral key.
    pub fn server_ephemeral_key(&mut self, key: ServerEphemKey) -> &mut Self {
        self.state.server_ephemeral_key = Some(key);
        self
    }

    /// Sets the encoding seed.
    pub fn encoding_seed(&mut self, seed: Vec<u8>) -> &mut Self {
        self.state.encoding_seed = Some(seed);
        self
    }

    /// Builds the attestation.
    pub fn build(self, provider: &CryptoProvider) -> Result<Attestation, AttestationBuilderError> {
        let Sign {
            signature_alg,
            hash_alg,
            connection_info,
            server_ephemeral_key,
            cert_commitment,
            encoding_commitment_root,
            encoding_seed,
        } = self.state;

        let hasher = provider.hash.get(&hash_alg).map_err(|_| {
            AttestationBuilderError::new(
                ErrorKind::Config,
                format!("accepted hash algorithm {hash_alg} but it's missing in the provider"),
            )
        })?;
        let signer = provider.signer.get(&signature_alg).map_err(|_| {
            AttestationBuilderError::new(
                ErrorKind::Config,
                format!(
                    "accepted signature algorithm {signature_alg} but it's missing in the provider"
                ),
            )
        })?;

        let encoding_commitment = if let Some(root) = encoding_commitment_root {
            let Some(seed) = encoding_seed else {
                return Err(AttestationBuilderError::new(
                    ErrorKind::Field,
                    "encoding commitment requested but seed was not set",
                ));
            };

            Some(EncodingCommitment { root, seed })
        } else {
            None
        };

        let mut field_id = FieldId::default();

        let body = Body {
            verifying_key: field_id.next(signer.verifying_key()),
            connection_info: field_id.next(connection_info.ok_or_else(|| {
                AttestationBuilderError::new(ErrorKind::Field, "connection info was not set")
            })?),
            server_ephemeral_key: field_id.next(server_ephemeral_key.ok_or_else(|| {
                AttestationBuilderError::new(ErrorKind::Field, "handshake data was not set")
            })?),
            cert_commitment: field_id.next(cert_commitment),
            encoding_commitment: encoding_commitment.map(|commitment| field_id.next(commitment)),
            plaintext_hashes: Default::default(),
        };

        let header = Header {
            id: thread_rng().gen(),
            version: VERSION,
            root: body.root(hasher),
        };

        let signature = signer
            .sign(&CanonicalSerialize::serialize(&header))
            .map_err(|err| AttestationBuilderError::new(ErrorKind::Signature, err))?;

        Ok(Attestation {
            signature,
            header,
            body,
        })
    }
}

/// Error for [`AttestationBuilder`].
#[derive(Debug, thiserror::Error)]
pub struct AttestationBuilderError {
    kind: ErrorKind,
    source: Option<Box<dyn Error + Send + Sync + 'static>>,
}

#[derive(Debug)]
enum ErrorKind {
    Request,
    Config,
    Field,
    Signature,
}

impl AttestationBuilderError {
    fn new<E>(kind: ErrorKind, error: E) -> Self
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self {
            kind,
            source: Some(error.into()),
        }
    }

    /// Returns whether the error originates from a bad request.
    pub fn is_request(&self) -> bool {
        matches!(self.kind, ErrorKind::Request)
    }
}

impl std::fmt::Display for AttestationBuilderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            ErrorKind::Request => f.write_str("request error")?,
            ErrorKind::Config => f.write_str("config error")?,
            ErrorKind::Field => f.write_str("field error")?,
            ErrorKind::Signature => f.write_str("signature error")?,
        }

        if let Some(source) = &self.source {
            write!(f, " caused by: {}", source)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use rstest::{fixture, rstest};
    use tlsn_data_fixtures::http::{request::GET_WITH_HEADER, response::OK_JSON};

    use crate::{
        connection::{HandshakeData, HandshakeDataV1_2},
        fixtures::{encoder_seed, encoding_provider, ConnectionFixture},
        hash::Blake3,
        request::RequestConfig,
        transcript::{encoding::EncodingTree, Transcript, TranscriptCommitConfigBuilder},
    };

    use super::*;

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

    #[fixture]
    #[once]
    fn default_attestation_config() -> AttestationConfig {
        AttestationConfig::builder()
            .supported_signature_algs([SignatureAlgId::SECP256K1])
            .build()
            .unwrap()
    }

    #[fixture]
    #[once]
    fn crypto_provider() -> CryptoProvider {
        let mut provider = CryptoProvider::default();
        provider.signer.set_secp256k1(&[42u8; 32]).unwrap();
        provider
    }

    #[rstest]
    fn test_attestation_builder_accept_unsupported_signer() {
        let (request, _) = request_and_connection();
        let attestation_config = AttestationConfig::builder()
            .supported_signature_algs([SignatureAlgId::SECP256R1])
            .build()
            .unwrap();

        let err = Attestation::builder(&attestation_config)
            .accept_request(request)
            .err()
            .unwrap();
        assert!(err.is_request());
    }

    #[rstest]
    fn test_attestation_builder_accept_unsupported_hasher() {
        let (request, _) = request_and_connection();

        let attestation_config = AttestationConfig::builder()
            .supported_signature_algs([SignatureAlgId::SECP256K1])
            .supported_hash_algs([HashAlgId::KECCAK256])
            .build()
            .unwrap();

        let err = Attestation::builder(&attestation_config)
            .accept_request(request)
            .err()
            .unwrap();
        assert!(err.is_request());
    }

    #[rstest]
    fn test_attestation_builder_accept_unsupported_encoding_commitment() {
        let (request, _) = request_and_connection();

        let attestation_config = AttestationConfig::builder()
            .supported_signature_algs([SignatureAlgId::SECP256K1])
            .supported_fields([
                FieldKind::ConnectionInfo,
                FieldKind::ServerEphemKey,
                FieldKind::ServerIdentityCommitment,
            ])
            .build()
            .unwrap();

        let err = Attestation::builder(&attestation_config)
            .accept_request(request)
            .err()
            .unwrap();
        assert!(err.is_request());
    }

    #[rstest]
    fn test_attestation_builder_sign_missing_signer(
        default_attestation_config: &AttestationConfig,
    ) {
        let (request, _) = request_and_connection();

        let attestation_builder = Attestation::builder(default_attestation_config)
            .accept_request(request.clone())
            .unwrap();

        let mut provider = CryptoProvider::default();
        provider.signer.set_secp256r1(&[42u8; 32]).unwrap();

        let err = attestation_builder.build(&provider).err().unwrap();
        assert!(matches!(err.kind, ErrorKind::Config));
    }

    #[rstest]
    fn test_attestation_builder_sign_missing_encoding_seed(
        default_attestation_config: &AttestationConfig,
        crypto_provider: &CryptoProvider,
    ) {
        let (request, connection) = request_and_connection();

        let mut attestation_builder = Attestation::builder(default_attestation_config)
            .accept_request(request.clone())
            .unwrap();

        let ConnectionFixture {
            connection_info,
            server_cert_data,
            ..
        } = connection;

        let HandshakeData::V1_2(HandshakeDataV1_2 {
            server_ephemeral_key,
            ..
        }) = server_cert_data.handshake.clone();

        attestation_builder
            .connection_info(connection_info.clone())
            .server_ephemeral_key(server_ephemeral_key);

        let err = attestation_builder.build(crypto_provider).err().unwrap();
        assert!(matches!(err.kind, ErrorKind::Field));
    }

    #[rstest]
    fn test_attestation_builder_sign_missing_server_ephemeral_key(
        default_attestation_config: &AttestationConfig,
        crypto_provider: &CryptoProvider,
    ) {
        let (request, connection) = request_and_connection();

        let mut attestation_builder = Attestation::builder(default_attestation_config)
            .accept_request(request.clone())
            .unwrap();

        let ConnectionFixture {
            connection_info, ..
        } = connection;

        attestation_builder
            .connection_info(connection_info.clone())
            .encoding_seed(encoder_seed().to_vec());

        let err = attestation_builder.build(crypto_provider).err().unwrap();
        assert!(matches!(err.kind, ErrorKind::Field));
    }

    #[rstest]
    fn test_attestation_builder_sign_missing_connection_info(
        default_attestation_config: &AttestationConfig,
        crypto_provider: &CryptoProvider,
    ) {
        let (request, connection) = request_and_connection();

        let mut attestation_builder = Attestation::builder(default_attestation_config)
            .accept_request(request.clone())
            .unwrap();

        let ConnectionFixture {
            server_cert_data, ..
        } = connection;

        let HandshakeData::V1_2(HandshakeDataV1_2 {
            server_ephemeral_key,
            ..
        }) = server_cert_data.handshake.clone();

        attestation_builder
            .server_ephemeral_key(server_ephemeral_key)
            .encoding_seed(encoder_seed().to_vec());

        let err = attestation_builder.build(crypto_provider).err().unwrap();
        assert!(matches!(err.kind, ErrorKind::Field));
    }
}
