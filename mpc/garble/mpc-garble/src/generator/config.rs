use derive_builder::Builder;

/// Generator configuration.
#[derive(Debug, Clone, Builder)]
pub struct GeneratorConfig {
    /// Whether to send commitments to output encodings.
    #[builder(default = "false", setter(custom))]
    pub(crate) encoding_commitments: bool,
    /// The batch size for encrypted gates sent to the evaluator.
    #[builder(default = "1024")]
    pub(crate) batch_size: usize,
}

impl GeneratorConfigBuilder {
    /// Enable encoding commitments.
    pub fn encoding_commitments(&mut self) -> &mut Self {
        self.encoding_commitments = Some(true);
        self
    }
}

impl Default for GeneratorConfig {
    fn default() -> Self {
        GeneratorConfigBuilder::default().build().unwrap()
    }
}
