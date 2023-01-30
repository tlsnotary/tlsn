use p256::elliptic_curve::sec1::ToEncodedPoint;

use crate::KeyExchangeError;

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum KeyExchangeMessage {
    PublicKey(PublicKey),
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum PublicKey {
    P256(Vec<u8>),
}

impl From<p256::PublicKey> for PublicKey {
    fn from(key: p256::PublicKey) -> Self {
        Self::P256(key.as_affine().to_encoded_point(false).as_bytes().to_vec())
    }
}

impl TryFrom<PublicKey> for p256::PublicKey {
    type Error = KeyExchangeError;

    fn try_from(key: PublicKey) -> Result<Self, Self::Error> {
        match key {
            PublicKey::P256(sec1_bytes) => {
                let pk = p256::PublicKey::from_sec1_bytes(&sec1_bytes)
                    .map_err(|e| KeyExchangeError::KeyParseError(e.to_string()))?;

                Ok(pk)
            }
        }
    }
}
