use derive_builder::Builder;

#[derive(Debug, Clone, Builder)]
pub struct OTSenderConfig {
    pub count: usize,
}

impl OTSenderConfig {
    /// Creates a new builder for the OT sender configuration
    pub fn builder() -> OTSenderConfigBuilder {
        OTSenderConfigBuilder::default()
    }
}

#[derive(Debug, Clone, Builder)]
pub struct OTReceiverConfig {
    pub count: usize,
}

impl OTReceiverConfig {
    /// Creates a new builder for the OT receiver configuration
    pub fn builder() -> OTReceiverConfigBuilder {
        OTReceiverConfigBuilder::default()
    }
}
