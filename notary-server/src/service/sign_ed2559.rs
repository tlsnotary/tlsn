use ed25519_dalek::SigningKey;
use ed25519_dalek::{Signature, Signer, Verifier};
/// Signer256k1 to generate Scp256k1 signature
pub(crate) struct SignerEd25519 {
    private_key: [u8; 32],
    pub signing_key: SigningKey,
}

impl SignerEd25519 {
    // Set a new signer. Private_key is 32 bytes hex key, witout 0x prefix
    pub(crate) fn new(private_key: String) -> SignerEd25519 {
        let private_key: [u8; 32] = hex::decode(private_key).unwrap().try_into().unwrap();
        let signing_key: SigningKey = SigningKey::from_bytes(&private_key);

        SignerEd25519 {
            private_key,
            signing_key,
        }
    }

    pub(crate) fn sign(&self, message: String) -> Signature {
        self.signing_key.sign(message.as_bytes())
    }

    pub(crate) fn verify(&self, message: String, signature: Signature) -> bool {
        self.signing_key
            .verify(message.as_bytes(), &signature)
            .is_ok()
    }
}

mod test {
    use super::Signature;
    use super::SignerEd25519;
    #[test]
    fn test2() {
        let private_key_env = std::env::var("NOTARY_PRIVATE_KEY_SECP256k1").unwrap();
        println!("private_key {:}", private_key_env);
        let signer = SignerEd25519::new(private_key_env);
        println!("signing_key {:#?}", signer.signing_key);

        let message: String = String::from("This is a test of the tsunami alert system.");
        let signature: Signature = signer.sign(message.clone());
        assert!(signer.verify(message, signature));
    }
}
