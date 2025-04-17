use std::error::Error;

use rand::{rng, Rng};

use crate::{
    attestation::{
        Attestation, AttestationConfig, Body, EncodingCommitment, Extension, FieldId, FieldKind,
        Header, ServerCertCommitment, VERSION,
    },
    connection::{ConnectionInfo, ServerEphemKey},
    hash::{HashAlgId, TypedHash},
    request::Request,
    serialize::CanonicalSerialize,
    signing::SignatureAlgId,
    transcript::encoding::EncoderSecret,
    CryptoProvider,
};

/// Attestation builder state for accepting a request.
#[derive(Debug)]
pub struct Accept {}

#[derive(Debug)]
pub struct Sign {
    signature_alg: SignatureAlgId,
    hash_alg: HashAlgId,
    connection_info: Option<ConnectionInfo>,
    server_ephemeral_key: Option<ServerEphemKey>,
    cert_commitment: ServerCertCommitment,
    encoding_commitment_root: Option<TypedHash>,
    encoder_secret: Option<EncoderSecret>,
    extensions: Vec<Extension>,
}

/// An attestation builder.
#[derive(Debug)]
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
            extensions,
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

        if let Some(validator) = config.extension_validator() {
            validator(&extensions)
                .map_err(|err| AttestationBuilderError::new(ErrorKind::Extension, err))?;
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
                encoder_secret: None,
                extensions,
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

    /// Sets the encoder secret.
    pub fn encoder_secret(&mut self, secret: EncoderSecret) -> &mut Self {
        self.state.encoder_secret = Some(secret);
        self
    }

    /// Adds an extension to the attestation.
    pub fn extension(&mut self, extension: Extension) -> &mut Self {
        self.state.extensions.push(extension);
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
            encoder_secret,
            extensions,
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
            let Some(secret) = encoder_secret else {
                return Err(AttestationBuilderError::new(
                    ErrorKind::Field,
                    "encoding commitment requested but encoder_secret was not set",
                ));
            };

            Some(EncodingCommitment { root, secret })
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
            extensions: extensions
                .into_iter()
                .map(|extension| field_id.next(extension))
                .collect(),
        };

        let header = Header {
            id: rng().random(),
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
    Extension,
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
            ErrorKind::Extension => f.write_str("extension error")?,
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
        fixtures::{
            encoder_secret, encoding_provider, request_fixture, ConnectionFixture, RequestFixture,
        },
        hash::Blake3,
        transcript::Transcript,
    };

    use super::*;

    #[fixture]
    #[once]
    fn attestation_config() -> AttestationConfig {
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
        let transcript = Transcript::new(GET_WITH_HEADER, OK_JSON);
        let connection = ConnectionFixture::tlsnotary(transcript.length());

        let RequestFixture { request, .. } = request_fixture(
            transcript,
            encoding_provider(GET_WITH_HEADER, OK_JSON),
            connection,
            Blake3::default(),
            Vec::new(),
        );

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
        let transcript = Transcript::new(GET_WITH_HEADER, OK_JSON);
        let connection = ConnectionFixture::tlsnotary(transcript.length());

        let RequestFixture { request, .. } = request_fixture(
            transcript,
            encoding_provider(GET_WITH_HEADER, OK_JSON),
            connection,
            Blake3::default(),
            Vec::new(),
        );

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
        let transcript = Transcript::new(GET_WITH_HEADER, OK_JSON);
        let connection = ConnectionFixture::tlsnotary(transcript.length());

        let RequestFixture { request, .. } = request_fixture(
            transcript,
            encoding_provider(GET_WITH_HEADER, OK_JSON),
            connection,
            Blake3::default(),
            Vec::new(),
        );

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
    fn test_attestation_builder_sign_missing_signer(attestation_config: &AttestationConfig) {
        let transcript = Transcript::new(GET_WITH_HEADER, OK_JSON);
        let connection = ConnectionFixture::tlsnotary(transcript.length());

        let RequestFixture { request, .. } = request_fixture(
            transcript,
            encoding_provider(GET_WITH_HEADER, OK_JSON),
            connection,
            Blake3::default(),
            Vec::new(),
        );

        let attestation_builder = Attestation::builder(attestation_config)
            .accept_request(request)
            .unwrap();

        let mut provider = CryptoProvider::default();
        provider.signer.set_secp256r1(&[42u8; 32]).unwrap();

        let err = attestation_builder.build(&provider).err().unwrap();
        assert!(matches!(err.kind, ErrorKind::Config));
    }

    #[rstest]
    fn test_attestation_builder_sign_missing_encoding_seed(
        attestation_config: &AttestationConfig,
        crypto_provider: &CryptoProvider,
    ) {
        let transcript = Transcript::new(GET_WITH_HEADER, OK_JSON);
        let connection = ConnectionFixture::tlsnotary(transcript.length());

        let RequestFixture { request, .. } = request_fixture(
            transcript,
            encoding_provider(GET_WITH_HEADER, OK_JSON),
            connection.clone(),
            Blake3::default(),
            Vec::new(),
        );

        let mut attestation_builder = Attestation::builder(attestation_config)
            .accept_request(request)
            .unwrap();

        let ConnectionFixture {
            connection_info,
            server_cert_data,
            ..
        } = connection;

        let HandshakeData::V1_2(HandshakeDataV1_2 {
            server_ephemeral_key,
            ..
        }) = server_cert_data.handshake;

        attestation_builder
            .connection_info(connection_info)
            .server_ephemeral_key(server_ephemeral_key);

        let err = attestation_builder.build(crypto_provider).err().unwrap();
        assert!(matches!(err.kind, ErrorKind::Field));
    }

    #[rstest]
    fn test_attestation_builder_sign_missing_server_ephemeral_key(
        attestation_config: &AttestationConfig,
        crypto_provider: &CryptoProvider,
    ) {
        let transcript = Transcript::new(GET_WITH_HEADER, OK_JSON);
        let connection = ConnectionFixture::tlsnotary(transcript.length());

        let RequestFixture { request, .. } = request_fixture(
            transcript,
            encoding_provider(GET_WITH_HEADER, OK_JSON),
            connection.clone(),
            Blake3::default(),
            Vec::new(),
        );

        let mut attestation_builder = Attestation::builder(attestation_config)
            .accept_request(request)
            .unwrap();

        let ConnectionFixture {
            connection_info, ..
        } = connection;

        attestation_builder
            .connection_info(connection_info)
            .encoder_secret(encoder_secret());

        let err = attestation_builder.build(crypto_provider).err().unwrap();
        assert!(matches!(err.kind, ErrorKind::Field));
    }

    #[rstest]
    fn test_attestation_builder_sign_missing_connection_info(
        attestation_config: &AttestationConfig,
        crypto_provider: &CryptoProvider,
    ) {
        let transcript = Transcript::new(GET_WITH_HEADER, OK_JSON);
        let connection = ConnectionFixture::tlsnotary(transcript.length());

        let RequestFixture { request, .. } = request_fixture(
            transcript,
            encoding_provider(GET_WITH_HEADER, OK_JSON),
            connection.clone(),
            Blake3::default(),
            Vec::new(),
        );

        let mut attestation_builder = Attestation::builder(attestation_config)
            .accept_request(request)
            .unwrap();

        let ConnectionFixture {
            server_cert_data, ..
        } = connection;

        let HandshakeData::V1_2(HandshakeDataV1_2 {
            server_ephemeral_key,
            ..
        }) = server_cert_data.handshake;

        attestation_builder
            .server_ephemeral_key(server_ephemeral_key)
            .encoder_secret(encoder_secret());

        let err = attestation_builder.build(crypto_provider).err().unwrap();
        assert!(matches!(err.kind, ErrorKind::Field));
    }

    #[rstest]
    fn test_attestation_builder_reject_extensions_by_default(
        attestation_config: &AttestationConfig,
    ) {
        let transcript = Transcript::new(GET_WITH_HEADER, OK_JSON);
        let connection = ConnectionFixture::tlsnotary(transcript.length());

        let RequestFixture { request, .. } = request_fixture(
            transcript,
            encoding_provider(GET_WITH_HEADER, OK_JSON),
            connection.clone(),
            Blake3::default(),
            vec![Extension {
                id: b"foo".to_vec(),
                value: b"bar".to_vec(),
            }],
        );

        let err = Attestation::builder(attestation_config)
            .accept_request(request)
            .unwrap_err();

        assert!(matches!(err.kind, ErrorKind::Extension));
    }

    #[rstest]
    fn test_attestation_builder_accept_extension(crypto_provider: &CryptoProvider) {
        let attestation_config = AttestationConfig::builder()
            .supported_signature_algs([SignatureAlgId::SECP256K1])
            .extension_validator(|_| Ok(()))
            .build()
            .unwrap();

        let transcript = Transcript::new(GET_WITH_HEADER, OK_JSON);
        let connection = ConnectionFixture::tlsnotary(transcript.length());

        let RequestFixture { request, .. } = request_fixture(
            transcript,
            encoding_provider(GET_WITH_HEADER, OK_JSON),
            connection.clone(),
            Blake3::default(),
            vec![Extension {
                id: b"foo".to_vec(),
                value: b"bar".to_vec(),
            }],
        );

        let mut attestation_builder = Attestation::builder(&attestation_config)
            .accept_request(request)
            .unwrap();

        let ConnectionFixture {
            server_cert_data,
            connection_info,
            ..
        } = connection;

        let HandshakeData::V1_2(HandshakeDataV1_2 {
            server_ephemeral_key,
            ..
        }) = server_cert_data.handshake;

        attestation_builder
            .connection_info(connection_info)
            .server_ephemeral_key(server_ephemeral_key)
            .encoder_secret(encoder_secret());

        let attestation = attestation_builder.build(crypto_provider).unwrap();

        assert_eq!(attestation.body.extensions().count(), 1);
    }
}
