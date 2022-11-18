use derive_builder::Builder;

const DEFAULT_OT_ID: &str = "FactoryParentOT";

#[derive(Debug, Default, Builder)]
pub struct SenderFactoryConfig {
    #[builder(default = "DEFAULT_OT_ID.to_string()")]
    pub(crate) ot_id: String,
    pub(crate) initial_count: usize,
}

#[derive(Debug, Default, Builder)]
pub struct ReceiverFactoryConfig {
    #[builder(default = "DEFAULT_OT_ID.to_string()")]
    pub(crate) ot_id: String,
    pub(crate) initial_count: usize,
}
