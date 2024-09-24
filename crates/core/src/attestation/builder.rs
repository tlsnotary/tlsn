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
