use crate::{
    attestation::FieldKind,
    hash::{HashAlgId, DEFAULT_SUPPORTED_HASH_ALGS},
    signing::SignatureAlgId,
};

const DEFAULT_SUPPORTED_FIELDS: &[FieldKind] = &[
    FieldKind::ConnectionInfo,
    FieldKind::ServerEphemKey,
    FieldKind::ServerIdentityCommitment,
    FieldKind::EncodingCommitment,
];

#[derive(Debug)]
#[allow(dead_code)]
enum ErrorKind {
    Builder,
}

impl std::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorKind::Builder => write!(f, "builder"),
        }
    }
}

/// Error for [`AttestationConfig`].
#[derive(Debug, thiserror::Error)]
#[error("attestation config error: kind: {kind}, reason: {reason}")]
pub struct AttestationConfigError {
    kind: ErrorKind,
    reason: String,
}

impl AttestationConfigError {
    #[allow(dead_code)]
    fn builder(reason: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::Builder,
            reason: reason.into(),
        }
    }
}

/// Attestation configuration.
#[derive(Debug, Clone)]
pub struct AttestationConfig {
    supported_signature_algs: Vec<SignatureAlgId>,
    supported_hash_algs: Vec<HashAlgId>,
    supported_fields: Vec<FieldKind>,
}

impl AttestationConfig {
    /// Creates a new builder.
    pub fn builder() -> AttestationConfigBuilder {
        AttestationConfigBuilder::default()
    }

    pub(crate) fn supported_signature_algs(&self) -> &[SignatureAlgId] {
        &self.supported_signature_algs
    }

    pub(crate) fn supported_hash_algs(&self) -> &[HashAlgId] {
        &self.supported_hash_algs
    }

    pub(crate) fn supported_fields(&self) -> &[FieldKind] {
        &self.supported_fields
    }
}

/// Builder for [`AttestationConfig`].
#[derive(Debug)]
pub struct AttestationConfigBuilder {
    supported_signature_algs: Vec<SignatureAlgId>,
    supported_hash_algs: Vec<HashAlgId>,
    supported_fields: Vec<FieldKind>,
}

impl Default for AttestationConfigBuilder {
    fn default() -> Self {
        Self {
            supported_signature_algs: Vec::default(),
            supported_hash_algs: DEFAULT_SUPPORTED_HASH_ALGS.to_vec(),
            supported_fields: DEFAULT_SUPPORTED_FIELDS.to_vec(),
        }
    }
}

impl AttestationConfigBuilder {
    /// Sets the supported signature algorithms.
    pub fn supported_signature_algs(
        &mut self,
        supported_signature_algs: impl Into<Vec<SignatureAlgId>>,
    ) -> &mut Self {
        self.supported_signature_algs = supported_signature_algs.into();
        self
    }

    /// Sets the supported hash algorithms.
    pub fn supported_hash_algs(
        &mut self,
        supported_hash_algs: impl Into<Vec<HashAlgId>>,
    ) -> &mut Self {
        self.supported_hash_algs = supported_hash_algs.into();
        self
    }

    /// Sets the supported attestation fields.
    pub fn supported_fields(&mut self, supported_fields: impl Into<Vec<FieldKind>>) -> &mut Self {
        self.supported_fields = supported_fields.into();
        self
    }

    /// Builds the configuration.
    pub fn build(&self) -> Result<AttestationConfig, AttestationConfigError> {
        Ok(AttestationConfig {
            supported_signature_algs: self.supported_signature_algs.clone(),
            supported_hash_algs: self.supported_hash_algs.clone(),
            supported_fields: self.supported_fields.clone(),
        })
    }
}
