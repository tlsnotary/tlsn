use derive_builder::Builder;

#[derive(Debug, Clone, Copy)]
pub enum Role {
    Leader,
    Follower,
}

#[derive(Debug, Clone, Builder)]
pub struct BlockCipherConfig {
    pub(crate) id: String,
    pub(crate) role: Role,
    #[builder(default = "0")]
    pub(crate) encoder_default_stream_id: u32,
}
