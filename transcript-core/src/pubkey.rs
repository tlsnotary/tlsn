use p256::{
    self,
    ecdsa::{signature::Verifier, Signature},
    EncodedPoint,
};

use crate::error::Error;

pub enum KeyType {
    P256,
}

/// A public key used by the Notary to sign the notarization session
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
            #[allow(unreachable_patterns)]
            _ => Err(Error::InternalError),
        }
    }

    /// Verifies a signature `sig` for the message `msg`
    pub fn verify_signature(&self, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        match *self {
            PubKey::P256(key) => {
                let signature = match Signature::from_der(sig) {
                    Ok(sig) => sig,
                    Err(_) => return Err(Error::SignatureVerificationError),
                };
                match key.verify(msg, &signature) {
                    Ok(_) => Ok(()),
                    Err(_) => Err(Error::SignatureVerificationError),
                }
            }
            #[allow(unreachable_patterns)]
            _ => Err(Error::InternalError),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::pubkey::{KeyType, PubKey};
    use p256::{
        self,
        ecdsa::{signature::Signer, SigningKey, VerifyingKey},
    };
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha12Rng;
    use rstest::{fixture, rstest};

    #[fixture]
    // Create a valid (piblic key, message, signature) tuple
    pub fn create_key_msg_sig() -> (PubKey, Vec<u8>, Vec<u8>) {
        let mut rng = ChaCha12Rng::from_seed([0; 32]);

        let signing_key = SigningKey::random(&mut rng);
        let verifying_key = VerifyingKey::from(&signing_key);
        let encoded = verifying_key.to_encoded_point(true);
        let pubkey_bytes = encoded.as_bytes();
        let key = PubKey::from_bytes(KeyType::P256, pubkey_bytes).unwrap();

        let msg: [u8; 16] = rng.gen();

        let signature = signing_key.sign(&msg);
        let sig_der = signature.to_der();
        let signature = sig_der.as_bytes();

        (key, msg.to_vec(), signature.to_vec())
    }

    #[rstest]
    // Expect verify_signature() to fail because the public key is wrong
    fn test_verify_signature_fail_wrong_key(create_key_msg_sig: (PubKey, Vec<u8>, Vec<u8>)) {
        let msg = create_key_msg_sig.1;
        let sig = create_key_msg_sig.2;

        // generate the wrong pubkey
        let mut rng = ChaCha12Rng::from_seed([1; 32]);

        let signing_key = SigningKey::random(&mut rng);
        let verifying_key = VerifyingKey::from(&signing_key);
        let encoded = verifying_key.to_encoded_point(true);
        let pubkey_bytes = encoded.as_bytes();
        let key = PubKey::from_bytes(KeyType::P256, pubkey_bytes).unwrap();

        assert!(
            key.verify_signature(&msg, &sig).err().unwrap() == Error::SignatureVerificationError
        );
    }

    #[rstest]
    // Expect verify_signature() to fail because the message is wrong
    fn test_verify_signature_fail_wrong_msg(create_key_msg_sig: (PubKey, Vec<u8>, Vec<u8>)) {
        let key = create_key_msg_sig.0;
        let sig = create_key_msg_sig.2;

        // generate the wrong msg
        let mut rng = ChaCha12Rng::from_seed([1; 32]);
        let msg: [u8; 16] = rng.gen();

        assert!(
            key.verify_signature(&msg, &sig).err().unwrap() == Error::SignatureVerificationError
        );
    }

    #[rstest]
    // Expect verify_signature() to fail because the signature is wrong
    fn test_verify_signature_fail_wrong_sig(create_key_msg_sig: (PubKey, Vec<u8>, Vec<u8>)) {
        let key = create_key_msg_sig.0;
        let msg = create_key_msg_sig.1;
        let mut sig = create_key_msg_sig.2;

        // corrupt a byte of signature
        sig[10] = sig[10].checked_add(1).unwrap_or(0);

        assert!(
            key.verify_signature(&msg, &sig).err().unwrap() == Error::SignatureVerificationError
        );
    }
}
