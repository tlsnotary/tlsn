use serde::{Deserialize, Serialize};

#[derive(Serialize, Clone, Deserialize)]
pub struct Cert(Vec<u8>);

impl Cert {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
}
