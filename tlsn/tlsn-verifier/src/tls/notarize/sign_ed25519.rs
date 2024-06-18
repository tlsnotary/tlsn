use ed25519_dalek::SigningKey;
use ed25519_dalek::{Signature, Signer, Verifier};
/// Signer256k1 to generate Scp256k1 signature
// pub(crate) struct SignerEd25519 {}

// impl SignerEd25519 {
//     // Set a new signer. Private_key is 32 bytes hex key, witout 0x prefix
//     // pub(crate) fn new() -> SignerEd25519 {
//     //     SignerEd25519 {}
//     // }

//     // ///display private & public key in compressed format
//     // pub(crate) fn print(&self) {
//     //     println!(
//     //         "ECDSA secp256k1 private key 0x{}",
//     //         &self.secret_key.display_secret().to_string()
//     //     );
//     //     println!(
//     //         "ECDSA secp256k1 compressed public key: 0x{}",
//     //         &self.public_key.to_string()
//     //     );
//     // }

//     // ///sign an ECDSA signature of a message with the private key
//     // /// Return a tuple with full signature and a 65-byte signature as expected in ethereum smart contracts
//     // pub(crate) fn sign(&self, data: String) -> (Signature, String) {
//     //     let secret_key = (&self).secret_key;

//     //     let digest = sha256::Hash::hash(data.as_bytes());
//     //     let message = Message::from_digest(digest.to_byte_array());

//     //     let signature = (&self).secp.sign_ecdsa(&message, &secret_key);

//     //     let last_byte = match &self.is_s_canonical(&signature) {
//     //         true => "1b",
//     //         false => "1c",
//     //     };

//     //     let signature_ethereum = format!(
//     //         "{}{}",
//     //         hex::encode(signature.serialize_compact()),
//     //         last_byte
//     //     );

//     //     (signature, signature_ethereum)
//     // }

//     // pub(crate) fn is_s_canonical(&self, signature: &Signature) -> bool {
//     //     // Get the `s` value from the signature

//     //     let signature_ = signature.serialize_compact();
//     //     let (_, s_bytes) = signature_.split_at(32);

//     //     // Convert `s_bytes` to `Scalar`
//     //     let s = Scalar::from_be_bytes(s_bytes.try_into().expect("length should be 32")).unwrap();
//     //     let curve_order = Scalar::from_le_bytes(CURVE_ORDER).unwrap();

//     //     // Check if `s` is in than the curve order
//     //     s <= curve_order
//     // }

//     // ///verify
//     // pub(crate) fn verify(&self, data: String, signature: Signature) -> Result<(), io::Error> {
//     //     let digest = sha256::Hash::hash(data.as_bytes());
//     //     let message = Message::from_digest(digest.to_byte_array());

//     //     let result = (&self)
//     //         .secp
//     //         .verify_ecdsa(&message, &signature, &(self).public_key);

//     //     match result {
//     //         Ok(result) => return Ok(()),
//     //         Err(err) => {
//     //             return Err(io::Error::new(
//     //                 io::ErrorKind::Other,
//     //                 "Signature verification failed",
//     //             ))
//     //         }
//     //     }
//     // }
// }

#[cfg(feature = "tracing")]
mod test {

    #[test]
    #[cfg(feature = "tracing")]
    fn test1() {
        use super::{Signature, Signer, SigningKey};

        let private_key_env = std::env::var("NOTARY_PRIVATE_KEY_SECP256k1").unwrap();

        let private_key: [u8; 32] = hex::decode(private_key_env).unwrap().try_into().unwrap();

        println!("private_key {:?}", private_key);

        let signing_key: SigningKey = SigningKey::from_bytes(&private_key);

        let message: &[u8] = b"This is a test of the tsunami alert system.";
        let signature: Signature = signing_key.sign(message);
        println!("signature {:?}", signature);
        println!("============================");
        println!(
            "==A : {:?},{}bytes",
            signing_key.verifying_key().to_bytes(),
            signing_key.verifying_key().to_bytes().len()
        );
        println!(
            "==R : {:?},{}bytes",
            signature.r_bytes(),
            signature.r_bytes().len()
        );
        println!(
            "==S : {:?},{}bytes",
            signature.s_bytes(),
            signature.s_bytes().len()
        );

        assert!(signing_key.verify(message, &signature).is_ok());
    }
}
