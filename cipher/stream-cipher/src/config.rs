use derive_builder::Builder;

#[derive(Debug, Clone, Builder)]
pub struct StreamCipherLeaderConfig {
    pub(crate) id: String,
    #[builder(default = "2")]
    pub(crate) start_ctr: usize,
    #[builder(default = "u32::MAX")]
    pub(crate) encoder_default_stream_id: u32,
    #[builder(default = "8")]
    pub(crate) concurrency: usize,
}

#[derive(Debug, Clone, Builder)]
pub struct StreamCipherFollowerConfig {
    pub(crate) id: String,
    #[builder(default = "2")]
    pub(crate) start_ctr: usize,
    #[builder(default = "u32::MAX")]
    pub(crate) encoder_default_stream_id: u32,
    #[builder(default = "0")]
    pub(crate) encoder_text_stream_id: u32,
    #[builder(default = "8")]
    pub(crate) concurrency: usize,
}
