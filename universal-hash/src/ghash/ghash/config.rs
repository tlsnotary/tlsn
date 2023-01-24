use derive_builder::Builder;

#[derive(Debug, Clone, Builder)]
pub struct GhashConfig {
    /// Initial number of block shares to provision
    #[builder(default = "1024")]
    pub initial_block_count: usize,
    /// Maximum number of blocks supported
    #[builder(default = "1024")]
    pub max_block_count: usize,
}
