use derive_builder::Builder;

/// Configuration for a block cipher.
#[derive(Debug, Clone, Builder)]
pub struct BlockCipherConfig {
    /// The ID of the block cipher.
    #[builder(setter(into))]
    pub(crate) id: String,
}

impl BlockCipherConfig {
    /// Creates a new builder for the block cipher configuration.
    pub fn builder() -> BlockCipherConfigBuilder {
        BlockCipherConfigBuilder::default()
    }
}
