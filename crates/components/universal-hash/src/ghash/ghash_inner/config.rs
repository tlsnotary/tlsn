use derive_builder::Builder;

#[derive(Debug, Clone, Builder)]
/// Configuration struct for [Ghash](crate::ghash::Ghash).
pub struct GhashConfig {
    /// Initial number of block shares to provision.
    #[builder(default = "1026")]
    pub initial_block_count: usize,
    /// Maximum number of blocks supported.
    #[builder(default = "1026")]
    pub max_block_count: usize,
}

impl GhashConfig {
    /// Creates a new builder for the [GhashConfig].
    pub fn builder() -> GhashConfigBuilder {
        GhashConfigBuilder::default()
    }
}
