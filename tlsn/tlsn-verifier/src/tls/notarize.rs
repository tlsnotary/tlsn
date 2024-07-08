//! This module handles the notarization phase of the verifier.
//!
//! The TLS verifier is only a notary.

use super::{config, state::Notarize, Verifier, VerifierError};
use futures::{FutureExt, SinkExt, StreamExt, TryFutureExt};
use mpz_core::serialize::CanonicalSerialize;
use mpz_share_conversion::ShareConversionVerify;
use signature::Signer;
use tlsn_core::{
    msg::{SessionTranscripts, SignedSessionHeader, TlsnMessage},
    HandshakeSummary, SessionHeader, Signature, Transcript,
};
use utils_aio::{expect_msg_or_err, mux::MuxChannel};

use bitcoin_hashes::{sha256, Hash};
use chrono::prelude::Utc;
use dotenv::dotenv;
use p256::ecdsa::{signature::Signer as Signer2, Signature as Signature2, SigningKey};
use std::env;
use uuid::Uuid;

mod sign;

// use super::airdrop;

#[cfg(feature = "tracing")]
use tracing::info;

impl Verifier<Notarize> {
    /// Notarizes the TLS session.
    pub async fn finalize<T>(self, signer: &impl Signer<T>) -> Result<SessionHeader, VerifierError>
    where
        T: Into<Signature>,
    {
        //info!("PPPPP Start finalize()");

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
            //info!("notarize_fut");
            let mut notarize_channel = mux_ctrl.get_channel("notarize").await?;

            let merkle_root =
                expect_msg_or_err!(notarize_channel, TlsnMessage::TranscriptCommitmentRoot)?;

            //info!("notarize_fut: ot_sender_actor");
            // Finalize all MPC before signing the session header
            let (mut ot_sender_actor, _, _) = futures::try_join!(
                ot_fut,
                ot_send.shutdown().map_err(VerifierError::from),
                ot_recv.shutdown().map_err(VerifierError::from)
            )?;

            //info!("notarize_fut: reveal");
            ot_sender_actor.reveal().await?;

            //info!("notarize_fut: finalize");
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

            ///// ECDSA signing
            dotenv::dotenv().ok();
            //ethereum 32 bytes private key without 0x in front
            let private_key = std::env::var("NOTARY_PRIVATE_KEY_SECP256k1").unwrap();
            //let private_key = String::from("<private_key>");

            // //parse user session data from transcripts
            // let session_transcripts =
            //     expect_msg_or_err!(notarize_channel, TlsnMessage::Transcripts)?;
            // let (host, user_id) = airdrop::parse_transcripts(session_transcripts);

            // let mut is_valid = airdrop::check_followers(user_id.clone()).await;

            // let (has_claim_key, mut claim_token) = airdrop::view_claim_key(user_id.clone()).await;

            // println!("is_valid = {:?}", is_valid);
            // println!("has_claim_key = {:?}", has_claim_key);
            // println!("claim_key = {:?}", claim_token);

            // if is_valid && !has_claim_key {
            //     claim_token = Uuid::new_v4().to_string();
            //     let inserted =
            //         airdrop::insert_claim_key(user_id.clone(), host.clone(), claim_token.clone())
            //             .await;
            //     println!("claim_token inserted = {:?}", inserted);

            //     if !inserted {
            //         is_valid = false;
            //     }
            // }

            //create nullifier from user_id & notary pkey
            //let nullifier_str = format!("{}{}{}", private_key, host, user_id);
            //let user_nullifier = sha256::Hash::hash(nullifier_str.as_bytes());

            // TODO: verify that user_nullifier is unique by making call to API
            //let private_key = String::from("PRIVATE_KEY");
            let signer: sign::Signer256k1 = sign::Signer256k1::new(private_key);

            let timestamp_str = Utc::now().timestamp();
            // let message = format!(
            //     "{};{};{};{}",
            //     host,
            //     timestamp_str,
            //     user_id,
            //     if is_valid {
            //         claim_token
            //     } else {
            //         "invalid".to_string()
            //     }
            // );

            #[cfg(feature = "tracing")]
            info!("Signed session header");
            info!("session_header {:?}", session_header);

            notarize_channel
                .send(TlsnMessage::SignedSessionHeader(SignedSessionHeader {
                    header: session_header.clone(),
                    signature: signature.into(),
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
    use super::*;
    // use serde::Serialize;
    // use serde_json::json;

    #[test]
    #[cfg(feature = "tracing")]
    fn test_signing_tls_session() {
        println!("test_signing_tls_session");
        let user_id = "43";

        dotenv::dotenv().ok();
        //ethereum 32 bytes private key without 0x in front
        let private_key = std::env::var("NOTARY_PRIVATE_KEY_SECP256k1").unwrap();
        let host = String::from("dummyjson.com");
        //create nullifier from user_id & notary pkey
        let nullifier_str = format!("{}{}{}", private_key, host, user_id);
        let user_nullifier = sha256::Hash::hash(nullifier_str.as_bytes());

        // TODO: verify that user_nullifier is unique by making call to API
        //let private_key = String::from("PRIVATE_KEY");
        let signer: sign::Signer256k1 = sign::Signer256k1::new(private_key);

        // Get the current timestamp
        let timestamp_str = Utc::now().timestamp();

        let message = format!("ETERNIS;{};{}", timestamp_str, user_nullifier);
        //ahi
        let (_, signature_ethereum) = signer.sign(message.clone());

        #[cfg(feature = "tracing")]
        println!("message {}", message);

        println!("signature 0x{}", signature_ethereum);
    }
}
