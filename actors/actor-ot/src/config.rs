use derive_builder::Builder;

const DEFAULT_OT_ID: &str = "ParentOT";

#[derive(Debug, Default, Builder)]
pub struct OTActorSenderConfig {
    #[builder(default = "DEFAULT_OT_ID.to_string()")]
    pub(crate) ot_id: String,
    pub(crate) initial_count: usize,
    #[builder(default = "false", setter(custom))]
    pub(crate) committed: bool,
}

impl OTActorSenderConfigBuilder {
    pub fn committed(&mut self) -> &mut Self {
        self.committed = Some(true);
        self
    }
}

#[derive(Debug, Default, Builder)]
pub struct OTActorReceiverConfig {
    #[builder(default = "DEFAULT_OT_ID.to_string()")]
    pub(crate) ot_id: String,
    pub(crate) initial_count: usize,
    #[builder(default = "false", setter(custom))]
    pub(crate) committed: bool,
}

impl OTActorReceiverConfigBuilder {
    pub fn committed(&mut self) -> &mut Self {
        self.committed = Some(true);
        self
    }
}
