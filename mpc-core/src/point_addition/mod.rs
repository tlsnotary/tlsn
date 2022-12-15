/// NIST P-256 Prime
pub const P: &str = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";

/// Additive secret share of resulting X coordinate
#[derive(Clone, Copy)]
pub struct P256SecretShare(pub(crate) [u8; 32]);

impl P256SecretShare {
    /// Creates new secret share
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Errors that may occur when using the point_addition module
#[derive(Debug, thiserror::Error)]
pub enum PointAdditionError {
    #[error("Protocol generated invalid P256 key share")]
    InvalidKeyshare,
}
