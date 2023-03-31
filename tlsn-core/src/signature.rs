use p256;
use serde::ser::{Serialize, Serializer};

#[derive(Clone)]
pub enum Signature {
    P256(p256::ecdsa::Signature),
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match *self {
            Signature::P256(ref s) => {
                serializer.serialize_newtype_variant("Signature", 0, "P256", &s.to_vec())
            }
        }
    }
}
