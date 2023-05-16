use p256;
use serde::{Deserialize, Serialize};

#[derive(Clone, Deserialize, Serialize)]
pub enum Signature {
    P256(p256::ecdsa::Signature),
}
