use derive_builder::Builder;

/// OT sender actor configuration
#[derive(Debug, Clone, Default, Builder)]
pub struct OTActorSenderConfig {
    /// The ID of the sender
    #[builder(setter(into))]
    pub(crate) id: String,
    /// The number of OTs to set up
    pub(crate) initial_count: usize,
    /// Whether the sender should commit to the OTs
    #[builder(default = "false", setter(custom))]
    pub(crate) committed: bool,
}

impl OTActorSenderConfig {
    /// Creates a new builder for the OT sender actor configuration
    pub fn builder() -> OTActorSenderConfigBuilder {
        OTActorSenderConfigBuilder::default()
    }

    /// Returns the ID of the sender
    pub fn id(&self) -> &str {
        &self.id
    }
}

impl OTActorSenderConfigBuilder {
    /// Sets the sender to commit to the OTs
    pub fn committed(&mut self) -> &mut Self {
        self.committed = Some(true);
        self
    }
}

/// OT receiver actor configuration
#[derive(Debug, Clone, Default, Builder)]
pub struct OTActorReceiverConfig {
    /// The ID of the receiver
    #[builder(setter(into))]
    pub(crate) id: String,
    /// The number of OTs to setup
    pub(crate) initial_count: usize,
    /// Whether the receiver should expect the sender to commit to the OTs
    #[builder(default = "false", setter(custom))]
    pub(crate) committed: bool,
}

impl OTActorReceiverConfig {
    /// Creates a new builder for the OT receiver actor configuration
    pub fn builder() -> OTActorReceiverConfigBuilder {
        OTActorReceiverConfigBuilder::default()
    }

    /// Returns the ID of the receiver
    pub fn id(&self) -> &str {
        &self.id
    }
}

impl OTActorReceiverConfigBuilder {
    /// Sets the receiver to expect the sender to commit to the OTs
    pub fn committed(&mut self) -> &mut Self {
        self.committed = Some(true);
        self
    }
}
