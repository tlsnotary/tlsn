use blake3::Hasher;

/// Outputs blake3 digest
pub(crate) fn blake3(data: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(data);
    hasher.finalize().into()
}
