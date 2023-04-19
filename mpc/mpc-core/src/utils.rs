//! Utilities for MPC protocols

/// Returns the blake3 hash of the given data.
pub fn blake3(data: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(data);
    hasher.finalize().into()
}
