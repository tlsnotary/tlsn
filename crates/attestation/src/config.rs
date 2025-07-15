use std::{fmt::Debug, sync::Arc};

use tlsn_core::hash::HashAlgId;

use crate::{
    Extension, InvalidExtension, hash::DEFAULT_SUPPORTED_HASH_ALGS, signing::SignatureAlgId,
};

type ExtensionValidator = Arc<dyn Fn(&[Extension]) -> Result<(), InvalidExtension> + Send + Sync>;

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
#[derive(Clone)]
pub struct AttestationConfig {
    supported_signature_algs: Vec<SignatureAlgId>,
    supported_hash_algs: Vec<HashAlgId>,
    extension_validator: Option<ExtensionValidator>,
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

    pub(crate) fn extension_validator(&self) -> Option<&ExtensionValidator> {
        self.extension_validator.as_ref()
    }
}

impl Debug for AttestationConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttestationConfig")
            .field("supported_signature_algs", &self.supported_signature_algs)
            .field("supported_hash_algs", &self.supported_hash_algs)
            .finish_non_exhaustive()
    }
}

/// Builder for [`AttestationConfig`].
pub struct AttestationConfigBuilder {
    supported_signature_algs: Vec<SignatureAlgId>,
    supported_hash_algs: Vec<HashAlgId>,
    extension_validator: Option<ExtensionValidator>,
}

impl Default for AttestationConfigBuilder {
    fn default() -> Self {
        Self {
            supported_signature_algs: Vec::default(),
            supported_hash_algs: DEFAULT_SUPPORTED_HASH_ALGS.to_vec(),
            extension_validator: Some(Arc::new(|e| {
                if !e.is_empty() {
                    Err(InvalidExtension::new(
                        "all extensions are disallowed by default",
                    ))
                } else {
                    Ok(())
                }
            })),
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

    /// Sets the extension validator.
    ///
    /// # Example
    /// ```
    /// # use tlsn_attestation::{AttestationConfig, InvalidExtension};
    /// # let mut builder = AttestationConfig::builder();
    /// builder.extension_validator(|extensions| {
    ///     for extension in extensions {
    ///         if extension.id != b"example.type" {
    ///             return Err(InvalidExtension::new("invalid extension type"));
    ///         }
    ///     }
    ///     Ok(())
    /// });
    /// ```
    pub fn extension_validator<F>(&mut self, f: F) -> &mut Self
    where
        F: Fn(&[Extension]) -> Result<(), InvalidExtension> + Send + Sync + 'static,
    {
        self.extension_validator = Some(Arc::new(f));
        self
    }

    /// Builds the configuration.
    pub fn build(&self) -> Result<AttestationConfig, AttestationConfigError> {
        Ok(AttestationConfig {
            supported_signature_algs: self.supported_signature_algs.clone(),
            supported_hash_algs: self.supported_hash_algs.clone(),
            extension_validator: self.extension_validator.clone(),
        })
    }
}

impl Debug for AttestationConfigBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttestationConfigBuilder")
            .field("supported_signature_algs", &self.supported_signature_algs)
            .field("supported_hash_algs", &self.supported_hash_algs)
            .finish_non_exhaustive()
    }
}
