use crate::{error::Error, signature::Signature};
use p256::{ecdsa::signature::Verifier, EncodedPoint};
use serde::ser::{Serialize, Serializer};

pub enum KeyType {
    P256,
}

/// A public key used by the Notary to sign the notarization session
#[derive(Clone)]
pub enum PubKey {
    P256(p256::ecdsa::VerifyingKey),
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
                Ok(PubKey::P256(vk))
            }
        }
    }

    /// Verifies a signature `sig` for the message `msg`
    pub fn verify(&self, msg: &impl Serialize, sig: &Signature) -> Result<(), Error> {
        let msg = bincode::serialize(msg).map_err(|_| Error::SerializationError)?;

        match (self, sig) {
            // pubkey and sig types must match
            (PubKey::P256(key), Signature::P256(sig)) => match key.verify(&msg, sig) {
                Ok(_) => Ok(()),
                Err(_) => Err(Error::SignatureVerificationError),
            },
        }
    }

    /// Returns the pubkey in the compressed SEC1 format
    /// TODO: will it have the leading 04
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            PubKey::P256(key) => key.to_encoded_point(true).to_bytes().to_vec(),
        }
    }
}

impl Serialize for PubKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match *self {
            PubKey::P256(ref p) => {
                serializer.serialize_newtype_variant("PubKey", 0, "P256", &p.to_encoded_point(true))
            }
        }
    }
}

impl Default for PubKey {
    fn default() -> Self {
        let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&[0u8; 32]).unwrap();
        PubKey::P256(key)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        pubkey::{KeyType, PubKey},
        signature::Signature,
    };
    use p256::{
        self,
        ecdsa::{signature::Signer, SigningKey, VerifyingKey},
    };
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha12Rng;
    use rstest::{fixture, rstest};

    #[fixture]
    // Create a valid (piblic key, message, signature) tuple
    pub fn create_key_msg_sig() -> (PubKey, Vec<u8>, Signature) {
        let mut rng = ChaCha12Rng::from_seed([0; 32]);

        let signing_key = SigningKey::random(&mut rng);
        let verifying_key = VerifyingKey::from(&signing_key);
        let encoded = verifying_key.to_encoded_point(true);
        let pubkey_bytes = encoded.as_bytes();
        let key = PubKey::from_bytes(KeyType::P256, pubkey_bytes).unwrap();

        let msg: [u8; 16] = rng.gen();

        let signature = Signature::P256(signing_key.sign(&msg));

        (key, msg.to_vec(), signature)
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
        let sig = match sig {
            Signature::P256(sig) => sig,
            _ => panic!(),
        };
        let mut bytes = sig.to_vec();
        bytes[10] = bytes[10].checked_add(1).unwrap_or(0);
        let sig = Signature::P256(p256::ecdsa::Signature::from_der(&bytes).unwrap());

        assert!(key.verify(&msg, &sig).err().unwrap() == Error::SignatureVerificationError);
    }
}
