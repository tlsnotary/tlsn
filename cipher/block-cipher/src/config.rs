use derive_builder::Builder;

/// Configuration for a block cipher
#[derive(Debug, Clone, Builder)]
pub struct BlockCipherConfig {
    /// The ID of the block cipher
    pub(crate) id: String,
}
