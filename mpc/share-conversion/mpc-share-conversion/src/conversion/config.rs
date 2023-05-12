use derive_builder::Builder;

/// Share conversion sender configuration.
#[derive(Debug, Clone, Builder)]
pub struct SenderConfig {
    /// The ID of the sender.
    #[builder(setter(into))]
    id: String,
    /// Whether recording is enabled.
    #[builder(default = "false", setter(custom))]
    record: bool,
}

impl SenderConfig {
    /// Creates a new builder.
    pub fn builder() -> SenderConfigBuilder {
        SenderConfigBuilder::default()
    }

    /// Returns the ID of the sender.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns whether recording is enabled.
    pub fn record(&self) -> bool {
        self.record
    }
}

impl SenderConfigBuilder {
    /// Enables recording of the protocol tape.
    pub fn record(&mut self) -> &mut Self {
        self.record = Some(true);
        self
    }
}

/// Share conversion receiver configuration.
#[derive(Debug, Clone, Builder)]
pub struct ReceiverConfig {
    /// The ID of the receiver.
    #[builder(setter(into))]
    id: String,
    /// Whether recording is enabled.
    #[builder(default = "false", setter(custom))]
    record: bool,
}

impl ReceiverConfig {
    /// Creates a new builder.
    pub fn builder() -> ReceiverConfigBuilder {
        ReceiverConfigBuilder::default()
    }

    /// Returns the ID of the receiver.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns whether recording is enabled.
    pub fn record(&self) -> bool {
        self.record
    }
}

impl ReceiverConfigBuilder {
    /// Enables recording of the protocol tape.
    pub fn record(&mut self) -> &mut Self {
        self.record = Some(true);
        self
    }
}
