use derive_builder::Builder;

#[derive(Debug, Clone, Builder)]
pub struct PRFLeaderConfig {
    id: String,
    #[builder(default = "u32::MAX")]
    encoder_default_stream_id: u32,
}

impl PRFLeaderConfig {
    /// Returns instance ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns default stream ID for encoder.
    pub fn encoder_default_stream_id(&self) -> u32 {
        self.encoder_default_stream_id
    }
}

#[derive(Debug, Clone, Builder)]
pub struct PRFFollowerConfig {
    id: String,
    #[builder(default = "u32::MAX")]
    encoder_default_stream_id: u32,
}

impl PRFFollowerConfig {
    /// Returns instance ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns default stream ID for encoder.
    pub fn encoder_default_stream_id(&self) -> u32 {
        self.encoder_default_stream_id
    }
}
