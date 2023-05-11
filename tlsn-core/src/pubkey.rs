use crate::{error::Error, signature::Signature};
use p256::{ecdsa::signature::Verifier, EncodedPoint};
use serde::{ser::Serializer, Deserialize, Deserializer, Serialize};

pub enum KeyType {
    P256,
}

#[derive(Clone)]
pub struct P256 {
    key: p256::ecdsa::VerifyingKey,
    is_compressed: bool,
}

impl P256 {
    pub fn new(key: p256::ecdsa::VerifyingKey, is_compressed: bool) -> Self {
        Self { key, is_compressed }
    }
}

impl Serialize for P256 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let point = self.key.to_encoded_point(self.is_compressed);
        serializer.serialize_bytes(point.as_bytes())
    }
}

impl<'de> Deserialize<'de> for P256 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        let point = match EncodedPoint::from_bytes(bytes) {
            Ok(point) => point,
            Err(_) => return Err(serde::de::Error::custom("deserialization error")),
        };
        let vk = match p256::ecdsa::VerifyingKey::from_encoded_point(&point) {
            Ok(vk) => vk,
            Err(_) => return Err(serde::de::Error::custom("deserialization error")),
        };
        Ok(P256::new(vk, point.is_compressed()))
    }
}

/// A public key
#[derive(Clone, Serialize, Deserialize)]
pub enum PubKey {
    P256(P256),
}

impl PubKey {
    /// Constructs pubkey from bytes
    pub fn from_bytes(typ: KeyType, bytes: &[u8]) -> Result<Self, Error> {
        match typ {
            KeyType::P256 => {
                let point = match EncodedPoint::from_bytes(bytes) {
                    Ok(point) => point,
                    Err(_) => return Err(Error::InternalError),
                };
                let vk = match p256::ecdsa::VerifyingKey::from_encoded_point(&point) {
                    Ok(vk) => vk,
                    Err(_) => return Err(Error::InternalError),
                };
                Ok(PubKey::P256(P256::new(vk, point.is_compressed())))
            }
        }
    }

    /// Verifies a signature `sig` for the message `msg`
    pub fn verify(&self, msg: &impl Serialize, sig: &Signature) -> Result<(), Error> {
        let msg = bincode::serialize(msg).map_err(|_| Error::SerializationError)?;

        match (self, sig) {
            // pubkey and sig types must match
            (PubKey::P256(p256), Signature::P256(sig)) => match p256.key.verify(&msg, sig) {
                Ok(_) => Ok(()),
                Err(_) => Err(Error::SignatureVerificationError),
            },
            #[allow(unreachable_patterns)]
            _ => Err(Error::SignatureAndPubkeyMismatch),
        }
    }

    /// Returns the pubkey in the SEC1 format (this format has a leading header byte)
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            PubKey::P256(p256) => p256
                .key
                .to_encoded_point(p256.is_compressed)
                .as_bytes()
                .to_vec(),
        }
    }
}

impl PartialEq for PubKey {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        pubkey::{KeyType, PubKey},
        signature::Signature,
        signer::Signer,
    };
    use p256::{
        self,
        ecdsa::{SigningKey, VerifyingKey},
    };
    use rand::{Rng, SeedableRng};
    use rand_chacha::{ChaCha12Rng, ChaCha20Rng};
    use rstest::{fixture, rstest};

    #[fixture]
    // Create a valid (public key, message, signature) tuple
    pub fn create_key_msg_sig() -> (PubKey, Vec<u8>, Signature) {
        let mut rng = ChaCha12Rng::from_seed([0; 32]);

        let raw_signing_key = SigningKey::random(&mut rng).to_bytes().to_vec();
        let signer = Signer::new(KeyType::P256, &raw_signing_key).unwrap();

        let pubkey = signer.verifying_key();

        let msg: [u8; 16] = rng.gen();
        let msg = msg.to_vec();

        let signature = signer.sign(&msg).unwrap();

        (pubkey, msg, signature)
    }

    #[rstest]
    // Expect verification to succeed
    fn test_verify_signature_success(create_key_msg_sig: (PubKey, Vec<u8>, Signature)) {
        let key = create_key_msg_sig.0;
        let msg = create_key_msg_sig.1;
        let sig = create_key_msg_sig.2;

        assert!(key.verify(&msg, &sig).is_ok());
    }

    #[rstest]
    // Expect verify_signature() to fail because the public key is wrong
    fn test_verify_signature_fail_wrong_key(create_key_msg_sig: (PubKey, Vec<u8>, Signature)) {
        let msg = create_key_msg_sig.1;
        let sig = create_key_msg_sig.2;

        // generate the wrong pubkey
        let mut rng = ChaCha12Rng::from_seed([1; 32]);

        let signing_key = SigningKey::random(&mut rng);
        let verifying_key = VerifyingKey::from(&signing_key);
        let encoded = verifying_key.to_encoded_point(true);
        let pubkey_bytes = encoded.as_bytes();
        let key = PubKey::from_bytes(KeyType::P256, pubkey_bytes).unwrap();

        assert!(key.verify(&msg, &sig).err().unwrap() == Error::SignatureVerificationError);
    }

    #[rstest]
    // Expect verify_signature() to fail because the message is wrong
    fn test_verify_signature_fail_wrong_msg(create_key_msg_sig: (PubKey, Vec<u8>, Signature)) {
        let key = create_key_msg_sig.0;
        let sig = create_key_msg_sig.2;

        // generate the wrong msg
        let mut rng = ChaCha12Rng::from_seed([1; 32]);
        let msg: [u8; 16] = rng.gen();

        assert!(key.verify(&msg, &sig).err().unwrap() == Error::SignatureVerificationError);
    }

    #[rstest]
    // Expect verify_signature() to fail because the signature is wrong
    fn test_verify_signature_fail_wrong_sig(create_key_msg_sig: (PubKey, Vec<u8>, Signature)) {
        let key = create_key_msg_sig.0;
        let msg = create_key_msg_sig.1;
        let sig = create_key_msg_sig.2;

        // corrupt a byte of signature
        let Signature::P256(sig) = sig;
        let der = sig.to_der();
        let mut bytes = der.as_bytes().to_owned();
        bytes[10] = bytes[10].checked_add(1).unwrap_or(0);
        let sig = Signature::P256(p256::ecdsa::Signature::from_der(&bytes).unwrap());

        assert!(key.verify(&msg, &sig).err().unwrap() == Error::SignatureVerificationError);
    }

    // Test our custom serialization/deserialization of P256
    #[test]
    fn test_serialize() {
        // Create a key and sign some data
        let rng = ChaCha20Rng::from_seed([6u8; 32]);
        let signing_key = p256::ecdsa::SigningKey::random(rng);
        let raw_key = signing_key.to_bytes();
        let raw_key = raw_key.as_slice();
        let signer = crate::signer::Signer::new(KeyType::P256, raw_key).unwrap();
        let data = vec![1u8; 32];
        let sig = signer.sign(&data).unwrap();

        // serialize the pubkey
        let pubkey = signer.verifying_key();
        let bytes = bincode::serialize(&pubkey).unwrap();

        // deserialize the pubkey
        let pubkey2: PubKey = bincode::deserialize(&bytes).unwrap();

        // make sure it is the same pubkey by verifying the signature and also by comparing directly
        assert!(pubkey2.verify(&data, &sig).is_ok());
        assert!(pubkey == pubkey2);
    }
}
