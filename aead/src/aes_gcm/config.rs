use derive_builder::Builder;

/// Protocol role
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Leader,
    Follower,
}

#[derive(Debug, Clone, Builder)]
pub struct AesGcmConfig {
    #[allow(dead_code)]
    id: String,
    role: Role,
}

impl AesGcmConfig {
    /// Returns the id of this instance
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the protocol role
    pub fn role(&self) -> &Role {
        &self.role
    }
}
