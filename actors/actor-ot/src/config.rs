use derive_builder::Builder;

/// OT sender actor configuration
#[derive(Debug, Default, Builder)]
pub struct OTActorSenderConfig {
    /// The ID of the sender
    pub(crate) id: String,
    /// The number of OTs to setup
    pub(crate) initial_count: usize,
    /// Whether the sender should commit to the OTs
    #[builder(default = "false", setter(custom))]
    pub(crate) committed: bool,
}

impl OTActorSenderConfigBuilder {
    /// Sets the sender to commit to the OTs
    pub fn committed(&mut self) -> &mut Self {
        self.committed = Some(true);
        self
    }
}

/// OT receiver actor configuration
#[derive(Debug, Default, Builder)]
pub struct OTActorReceiverConfig {
    /// The ID of the receiver
    pub(crate) id: String,
    /// The number of OTs to setup
    pub(crate) initial_count: usize,
    /// Whether the receiver should expect the sender to commit to the OTs
    #[builder(default = "false", setter(custom))]
    pub(crate) committed: bool,
}

impl OTActorReceiverConfigBuilder {
    /// Sets the receiver to expect the sender to commit to the OTs
    pub fn committed(&mut self) -> &mut Self {
        self.committed = Some(true);
        self
    }
}
