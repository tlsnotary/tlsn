use p256::{
    self,
    ecdsa::{signature::Verifier, Signature},
    EncodedPoint,
};

pub enum KeyType {
    P256,
}

pub enum PubKey {
    P256(p256::ecdsa::VerifyingKey),
}

impl PubKey {
    pub fn from_bytes(typ: KeyType, bytes: &[u8]) -> Self {
        match typ {
            KeyType::P256 => {
                let point = EncodedPoint::from_bytes(bytes).unwrap();
                PubKey::P256(p256::ecdsa::VerifyingKey::from_encoded_point(&point).unwrap())
            }
            _ => panic!(),
        }
    }

    pub fn verify_signature(&self, msg: &[u8], sig: &[u8]) -> bool {
        match *self {
            PubKey::P256(key) => {
                let signature = Signature::from_der(sig).unwrap();
                key.verify(msg, &signature).unwrap();
                true
            }
        }
    }
}

#[test]
fn test() {
    let key = PubKey::from_bytes(KeyType::P256, &[4; 32]);
}
