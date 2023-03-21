use derive_builder::Builder;

#[derive(Debug, Clone, Builder)]
pub struct AesGcmLeaderConfig {
    #[allow(dead_code)]
    pub(crate) id: String,
}

#[derive(Debug, Clone, Builder)]
pub struct AesGcmFollowerConfig {
    #[allow(dead_code)]
    pub(crate) id: String,
}
