use crate::{hash::HashAlgId, signing::SignatureAlgId};

/// Request configuration.
#[derive(Debug, Clone)]
pub struct RequestConfig {
    signature_alg: SignatureAlgId,
    hash_alg: HashAlgId,
}

impl Default for RequestConfig {
    fn default() -> Self {
        Self::builder().build().unwrap()
    }
}

impl RequestConfig {
    /// Creates a new builder.
    pub fn builder() -> RequestConfigBuilder {
        RequestConfigBuilder::default()
    }

    /// Returns the signature algorithm.
    pub fn signature_alg(&self) -> &SignatureAlgId {
        &self.signature_alg
    }

    /// Returns the hash algorithm.
    pub fn hash_alg(&self) -> &HashAlgId {
        &self.hash_alg
    }
}

/// Builder for [`RequestConfig`].
#[derive(Debug)]
pub struct RequestConfigBuilder {
    signature_alg: SignatureAlgId,
    hash_alg: HashAlgId,
}

impl Default for RequestConfigBuilder {
    fn default() -> Self {
        Self {
            signature_alg: SignatureAlgId::SECP256K1,
            hash_alg: HashAlgId::BLAKE3,
        }
    }
}

impl RequestConfigBuilder {
    /// Sets the signature algorithm.
    pub fn signature_alg(&mut self, signature_alg: SignatureAlgId) -> &mut Self {
        self.signature_alg = signature_alg;
        self
    }

    /// Sets the hash algorithm.
    pub fn hash_alg(&mut self, hash_alg: HashAlgId) -> &mut Self {
        self.hash_alg = hash_alg;
        self
    }

    /// Builds the config.
    pub fn build(self) -> Result<RequestConfig, RequestConfigBuilderError> {
        Ok(RequestConfig {
            signature_alg: self.signature_alg,
            hash_alg: self.hash_alg,
        })
    }
}

/// Error for [`RequestConfigBuilder`].
#[derive(Debug, thiserror::Error)]
#[error("request configuration builder error: {message}")]
pub struct RequestConfigBuilderError {
    message: String,
}
