//! This module handles the notarization phase of the verifier.
//!
//! The TLS verifier is only a notary.

use super::{config, state::Notarize, Verifier, VerifierError};
use futures::{FutureExt, SinkExt, StreamExt, TryFutureExt};
use mpz_core::serialize::CanonicalSerialize;
use mpz_share_conversion::ShareConversionVerify;
use signature::Signer;
use tlsn_core::{
    msg::{SignedSessionHeader, TlsnMessage},
    HandshakeSummary, SessionHeader, Signature,
};
use utils_aio::{expect_msg_or_err, mux::MuxChannel};

use p256::ecdsa::{signature::Signer as Signer2, Signature as Signature2, SigningKey};
use rand_core::OsRng;

#[cfg(feature = "tracing")]
use tracing::info;

impl Verifier<Notarize> {
    /// Notarizes the TLS session.
    pub async fn finalize<T>(self, signer: &impl Signer<T>) -> Result<SessionHeader, VerifierError>
    where
        T: Into<Signature>,
    {
        let Notarize {
            mut mux_ctrl,
            mut mux_fut,
            mut vm,
            ot_send,
            ot_recv,
            ot_fut,
            mut gf2,
            encoder_seed,
            start_time,
            server_ephemeral_key,
            handshake_commitment,
            sent_len,
            recv_len,
        } = self.state;

        let notarize_fut = async {
            let mut notarize_channel = mux_ctrl.get_channel("notarize").await?;

            let merkle_root =
                expect_msg_or_err!(notarize_channel, TlsnMessage::TranscriptCommitmentRoot)?;

            // Finalize all MPC before signing the session header
            let (mut ot_sender_actor, _, _) = futures::try_join!(
                ot_fut,
                ot_send.shutdown().map_err(VerifierError::from),
                ot_recv.shutdown().map_err(VerifierError::from)
            )?;

            ot_sender_actor.reveal().await?;

            vm.finalize()
                .await
                .map_err(|e| VerifierError::MpcError(Box::new(e)))?;

            gf2.verify()
                .await
                .map_err(|e| VerifierError::MpcError(Box::new(e)))?;

            #[cfg(feature = "tracing")]
            info!("Finalized all MPC");

            let handshake_summary =
                HandshakeSummary::new(start_time, server_ephemeral_key, handshake_commitment);

            let session_header = SessionHeader::new(
                encoder_seed,
                merkle_root,
                sent_len,
                recv_len,
                handshake_summary,
            );

            let signature = signer.sign(&session_header.to_bytes());

            let message = b"Eternis:Aadhar";

            info!("Signing message: :{:?}", message);

            let signature2 = signer.sign(&message.to_bytes()).into();

            ///// ECDSA signing

            #[cfg(feature = "tracing")]
            info!("Signed session header");

            notarize_channel
                .send(TlsnMessage::SignedSessionHeader(SignedSessionHeader {
                    header: session_header.clone(),
                    signature: signature.into(),
                    signature2: signature2.into(),
                }))
                .await?;

            #[cfg(feature = "tracing")]
            info!("Sent session header");

            Ok::<_, VerifierError>(session_header)
        };

        let session_header = futures::select! {
            res = notarize_fut.fuse() => res?,
            _ = &mut mux_fut => Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?,
        };

        let mut mux_ctrl = mux_ctrl.into_inner();

        futures::try_join!(mux_ctrl.close().map_err(VerifierError::from), mux_fut)?;

        Ok(session_header)
    }
}

#[cfg(feature = "tracing")]
mod test {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use mpz_core::serialize::CanonicalSerialize;
    use p256::ecdsa::{signature::Signer as Signer2, Signature as Signature2, SigningKey};
    use p256::ecdsa::{signature::Verifier, VerifyingKey};
    use rand_core::OsRng;

    use bitcoin_hashes::{sha256, Hash};
    use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};

    use std::{fmt::Write, num::ParseIntError};

    #[test]
    #[cfg(feature = "tracing")]
    fn test_p256_signature_rand() {
        let message = b"Eternis:Aadhar";

        let signing_key = SigningKey::random(&mut OsRng); // Serialize with `::to_bytes()`

        let signature: Signature2 = signing_key.sign(message);

        let verifying_key = VerifyingKey::from(&signing_key); // Serialize with `::to_encoded_point()`

        println!(
            "ECDSA randomly generated signing key {:?}",
            STANDARD.encode(signing_key.to_bytes())
        );
        println!(
            "ECDSA verifying key {:?}",
            STANDARD.encode(verifying_key.to_bytes())
        );
        println!(
            "ECDSA Signature {:?}",
            STANDARD.encode(signature.to_bytes())
        );

        assert!(verifying_key.verify(message, &signature).is_ok());
    }
    #[test]
    #[cfg(feature = "tracing")]
    fn test_p256_signature_from_bytes() {
        let message = b"Eternis:Aadhar";

        let bytes: [u8; 32] = [
            216, 90, 191, 172, 250, 143, 187, 38, 236, 136, 250, 197, 219, 205, 1, 101, 98, 83,
            245, 120, 126, 230, 46, 128, 51, 20, 147, 49, 29, 163, 30, 222,
        ];

        let signing_key = SigningKey::from_bytes(&bytes.into()).unwrap(); // Serialize with `::to_bytes()`

        let signature: Signature2 = signing_key.sign(message);

        let verifying_key = VerifyingKey::from(&signing_key); // Serialize with `::to_encoded_point()`

        println!("ECDSA signing key {:?}", signing_key.to_bytes());
        println!(
            "ECDSA signing key {}",
            STANDARD.encode(signing_key.to_bytes())
        );
        println!(
            "ECDSA verifying key {}",
            STANDARD.encode(verifying_key.to_bytes())
        );
        println!("ECDSA Signature {}", signature);

        assert!(verifying_key.verify(message, &signature).is_ok());
    }

    #[test]
    #[cfg(feature = "tracing")]
    fn test_secp256k1_signature_rand() {
        let secp = Secp256k1::new();
        let (secret_key, public_key) = secp.generate_keypair(&mut OsRng);
        let digest = sha256::Hash::hash("Hello World!".as_bytes());
        let message = Message::from_digest(digest.to_byte_array());

        println!("ECDSA secp256k1 private key {:?}", secret_key);
        println!("ECDSA secp256k1 public key {:?}", public_key);

        let sig = secp.sign_ecdsa(&message, &secret_key);
        assert!(secp.verify_ecdsa(&message, &sig, &public_key).is_ok());
    }

    #[test]
    #[cfg(feature = "tracing")]
    fn test_secp256k1_signature() {
        use bitcoin_hashes::hex::DisplayHex;
        use hex::encode;

        use std::{fmt::LowerHex, str::FromStr};

        let secp = Secp256k1::new();

        //let (secret_key, public_key) = secp.generate_keypair(&mut OsRng);

        let secretKey =
            SecretKey::from_str("7d8f5af6ed7106d3b8f0c80e13f9bd76bc03d166ecefbc67b28138669652f13d")
                .unwrap();

        let publicKey = PublicKey::from_secret_key(&secp, &secretKey);

        println!(
            "ECDSA secp256k1 private key 0x{}",
            secretKey.display_secret().to_string()
        );
        println!(
            "ECDSA secp256k1 compressed public key: 0x{}",
            publicKey.to_string()
        );

        //hashing according to ethereum EIP-191 standard
        // let digest =
        //     sha256::Hash::hash("\x19Ethereum Signed Message:\n14Eternis:Aadhar".as_bytes());
        //using prehashed value using EIP-191  ethereum standard
        // let encodedHex = <[u8; 32]>::from_hex(
        //     "c36dbb01b9f272ed3e090a6532cd3cac04f3dd6bf471677dec09bf1b15338276",
        // )
        // .unwrap();

        // simple hash
        let digest2 = sha256::Hash::hash("ahi".as_bytes());
        println!("Digest  {:?}", digest2.to_byte_array());

        let message = Message::from_digest(digest2.to_byte_array());
        println!("message  {:?}", message);

        // let sig = secp.sign_ecdsa(&message, &secretKey);
        // println!("72-byte ECDSA signature {:?}", sig);

        let sig = secp.sign_ecdsa(&message, &secretKey);
        println!(
            "64-byte ECDSA signature {}",
            hex::encode(sig.serialize_compact())
        );

        //generate ethereum address for public_key
        // let address = sha256::Hash::hash(public_key);
        // println!("Ethereum address {:?}", address);

        assert!(secp.verify_ecdsa(&message, &sig, &publicKey).is_ok());
    }
}
