use derive_builder::Builder;

const DEFAULT_OT_ID: &str = "FactoryParentOT";

#[derive(Debug, Default, Builder)]
pub struct SenderFactoryConfig {
    #[builder(default = "DEFAULT_OT_ID.to_string()")]
    pub(crate) ot_id: String,
    pub(crate) initial_count: usize,
    #[builder(default = "false", setter(custom))]
    pub(crate) committed: bool,
}

impl SenderFactoryConfigBuilder {
    pub fn committed(&mut self) -> &mut Self {
        self.committed = Some(true);
        self
    }
}

#[derive(Debug, Default, Builder)]
pub struct ReceiverFactoryConfig {
    #[builder(default = "DEFAULT_OT_ID.to_string()")]
    pub(crate) ot_id: String,
    pub(crate) initial_count: usize,
    #[builder(default = "false", setter(custom))]
    pub(crate) committed: bool,
}

impl ReceiverFactoryConfigBuilder {
    pub fn committed(&mut self) -> &mut Self {
        self.committed = Some(true);
        self
    }
}
