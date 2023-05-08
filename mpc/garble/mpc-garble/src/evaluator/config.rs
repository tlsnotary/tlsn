use derive_builder::Builder;

/// Evaluator configuration.
#[derive(Debug, Clone, Builder)]
pub struct EvaluatorConfig {
    /// Whether to expect commitments to output encodings from the generator.
    #[builder(default = "false", setter(custom))]
    pub(crate) encoding_commitments: bool,
    /// Whether to log circuits.
    #[builder(default = "false", setter(custom))]
    pub(crate) log_circuits: bool,
    /// Whether to log decodings.
    #[builder(default = "false", setter(custom))]
    pub(crate) log_decodings: bool,
    /// The number of encrypted gates to evaluate per batch.
    #[builder(default = "1024")]
    pub(crate) batch_size: usize,
}

impl EvaluatorConfigBuilder {
    /// Enable encoding commitments.
    pub fn encoding_commitments(&mut self) -> &mut Self {
        self.encoding_commitments = Some(true);
        self
    }

    /// Enable circuit logs.
    pub fn log_circuits(&mut self) -> &mut Self {
        self.log_circuits = Some(true);
        self
    }

    /// Enable decoding logs.
    pub fn log_decodings(&mut self) -> &mut Self {
        self.log_decodings = Some(true);
        self
    }
}
