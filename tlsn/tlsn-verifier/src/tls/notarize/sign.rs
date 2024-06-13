use bitcoin_hashes::{sha256, Hash};
use secp256k1::{All, Message, PublicKey, Scalar, Secp256k1, SecretKey};
use std::io::{self, Error};
use std::ops::Div;
use std::{result, str::FromStr};

use secp256k1::constants::CURVE_ORDER;
use secp256k1::ecdsa::Signature;
/// Signer256k1 to generate Scp256k1 signature
pub(crate) struct Signer256k1 {
    pub(crate) public_key: PublicKey,
    secret_key: SecretKey,
    secp: Secp256k1<All>,
}

impl Signer256k1 {
    /// Set a new signer. Private_key is 32 bytes hex key, witout 0x prefix
    pub(crate) fn new(private_key: String) -> Signer256k1 {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_str(&private_key).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        Signer256k1 {
            secret_key,
            public_key,
            secp,
        }
    }

    ///display private & public key in compressed format
    pub(crate) fn print(&self) {
        println!(
            "ECDSA secp256k1 private key 0x{}",
            &self.secret_key.display_secret().to_string()
        );
        println!(
            "ECDSA secp256k1 compressed public key: 0x{}",
            &self.public_key.to_string()
        );
    }

    ///sign an ECDSA signature of a message with the private key
    /// Return a tuple with full signature and a 65-byte signature as expected in ethereum smart contracts
    pub(crate) fn sign(&self, data: String) -> (Signature, String) {
        let secret_key = (&self).secret_key;

        let digest = sha256::Hash::hash(data.as_bytes());
        let message = Message::from_digest(digest.to_byte_array());

        let signature = (&self).secp.sign_ecdsa(&message, &secret_key);

        let last_byte = match &self.is_s_canonical(&signature) {
            true => "1b",
            false => "1c",
        };

        let signature_ethereum = format!(
            "{}{}",
            hex::encode(signature.serialize_compact()),
            last_byte
        );

        (signature, signature_ethereum)
    }

    pub(crate) fn is_s_canonical(&self, signature: &Signature) -> bool {
        // Get the `s` value from the signature

        let signature_ = signature.serialize_compact();
        let (_, s_bytes) = signature_.split_at(32);

        // Convert `s_bytes` to `Scalar`
        let s = Scalar::from_be_bytes(s_bytes.try_into().expect("length should be 32")).unwrap();
        let curve_order = Scalar::from_le_bytes(CURVE_ORDER).unwrap();

        // Check if `s` is in than the curve order
        s <= curve_order
    }

    ///verify
    pub(crate) fn verify(&self, data: String, signature: Signature) -> Result<(), io::Error> {
        let digest = sha256::Hash::hash(data.as_bytes());
        let message = Message::from_digest(digest.to_byte_array());

        let result = (&self)
            .secp
            .verify_ecdsa(&message, &signature, &(self).public_key);

        match result {
            Ok(result) => return Ok(()),
            Err(err) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Signature verification failed",
                ))
            }
        }
    }
}

#[cfg(feature = "tracing")]
mod test {
    use super::*;
    use chrono::prelude::Utc;

    #[test]
    #[cfg(feature = "tracing")]
    fn test_secp256k1_signature2() {
        dotenv::dotenv().ok();

        let private_key = std::env::var("NOTARY_PRIVATE_KEY_SECP256k1").unwrap();
        let signer: Signer256k1 = Signer256k1::new(private_key);

        let timestamp_str = Utc::now().timestamp();
        let message = format!("ETERNIS;{}", timestamp_str);

        let (signature, signature_ethereum) = signer.sign(message.clone());

        signer.print();
        println!("message to sign {}", message);
        println!("compact signature 0x{}", signature_ethereum);

        assert!(signer.verify(message.clone(), signature).is_ok());
    }
}
