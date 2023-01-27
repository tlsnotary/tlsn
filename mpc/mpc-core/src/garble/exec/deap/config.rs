use derive_builder::Builder;

#[derive(Debug, Clone, Builder)]
pub struct DEAPConfig {
    id: String,
}

impl DEAPConfig {
    pub fn id(&self) -> &str {
        &self.id
    }
}
