use derive_builder::Builder;

#[derive(Debug, Clone, Builder)]
pub struct DualExConfig {
    id: String,
}

impl DualExConfig {
    pub fn id(&self) -> &str {
        &self.id
    }
}
