use derive_builder::Builder;

#[derive(Debug, Clone, Builder)]
pub struct GhashConfig {
    /// The instance ID
    #[builder(setter(into))]
    pub id: String,
    /// Initial number of block shares to provision
    #[builder(default = "1024")]
    pub initial_block_count: usize,
    /// Maximum number of blocks supported
    #[builder(default = "1024")]
    pub max_block_count: usize,
}

impl GhashConfig {
    /// Returns a new GhashConfigBuilder
    pub fn builder() -> GhashConfigBuilder {
        GhashConfigBuilder::default()
    }
}
