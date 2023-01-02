use derive_builder::Builder;

#[derive(Debug, Clone, Builder)]
pub struct OTSenderConfig {
    pub count: usize,
}

#[derive(Debug, Clone, Builder)]
pub struct OTReceiverConfig {
    pub count: usize,
}
