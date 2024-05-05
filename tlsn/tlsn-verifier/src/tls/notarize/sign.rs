use bitcoin_hashes::{sha256, Hash};
use secp256k1::{All, Message, PublicKey, Secp256k1, SecretKey};
use std::io::{self, Error};
use std::{result, str::FromStr};

use secp256k1::ecdsa::Signature;

/// Signer to generate Scp256k1 signature
pub(crate) struct Signer {
    pub(crate) public_key: PublicKey,
    secret_key: SecretKey,
    secp: Secp256k1<All>,
}

impl Signer {
    /// Set a new signer. Private_key is 32 bytes hex key, witout 0x prefix
    pub(crate) fn new(private_key: String) -> Signer {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_str(&private_key).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        Signer {
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
    pub(crate) fn sign(&self, data: String) -> Signature {
        let secret_key = (&self).secret_key;

        let digest = sha256::Hash::hash(data.as_bytes());
        let message = Message::from_digest(digest.to_byte_array());

        (&self).secp.sign_ecdsa(&message, &secret_key)
    }

    ///verify ECDSA signature
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
                    "Signature erification failed",
                ))
            }
        }
    }
}

#[cfg(feature = "tracing")]
mod test {
    use super::*;

    #[test]
    #[cfg(feature = "tracing")]
    fn test_secp256k1_signature2() {
        use crate::tls::notarize::sign;

        dotenv::dotenv().ok();

        let private_key = std::env::var("NOTARY_PRIVATE_KEY_SECP256k1").unwrap();
        let signer: Signer = Signer::new(private_key);
        signer.print();

        let signature = signer.sign(String::from("ETERNIS"));

        println!(
            "64-byte ECDSA signature {}",
            hex::encode(signature.serialize_compact())
        );

        assert!(signer.verify(String::from("ETERNIS"), signature).is_ok());
    }
}
