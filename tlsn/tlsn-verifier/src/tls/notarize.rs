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
mod signEd25519;

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

            //parse user session data from transcripts
            let session_transcripts =
                expect_msg_or_err!(notarize_channel, TlsnMessage::Transcripts)?;
            let (host, user_id, uuid) = parse_transcripts(session_transcripts);

            //create nullifier from user_id & notary pkey
            //let nullifier_str = format!("{}{}{}", private_key, host, user_id);
            //let user_nullifier = sha256::Hash::hash(nullifier_str.as_bytes());

            // TODO: verify that user_nullifier is unique by making call to API
            //let private_key = String::from("PRIVATE_KEY");
            let signer: sign::Signer256k1 = sign::Signer256k1::new(private_key);

            let timestamp_str = Utc::now().timestamp();
            let message = format!("{};{};{};{}", host, timestamp_str, user_id, uuid);
            //ahi
            let (_, signature2) = signer.sign(message.clone());

            #[cfg(feature = "tracing")]
            info!("Signed session header");
            info!("session_header {:?}", session_header);

            notarize_channel
                .send(TlsnMessage::SignedSessionHeader(SignedSessionHeader {
                    header: session_header.clone(),
                    signature: signature.into(),
                    signature2,
                    message,
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

fn parse_transcripts(session_transcripts: SessionTranscripts) -> (String, String, String) {
    let transcript_tx_str =
        String::from_utf8_lossy(session_transcripts.transcript_tx.data()).to_string();
    let transcript_rx_str =
        String::from_utf8_lossy(session_transcripts.transcript_rx.data()).to_string();

    info!(" Received transcripts: {:?}", transcript_rx_str);

    let start_key = String::from("userName\":\"");
    let end_key = String::from("\"");
    let user_id: String = parse_value(transcript_rx_str, start_key, end_key);

    let start_key = String::from("host: ");
    let end_key = String::from("\r\n");
    let host: String = parse_value(transcript_tx_str, start_key, end_key);

    let uuid = Uuid::new_v4().to_string();
    info!("host {:?} user_id: {:?} uuid {:?}", host, user_id, uuid);
    info!("uid: {:?}", user_id);

    return (host, user_id, uuid);
}

fn parse_value(str: String, start_key: String, end_key: String) -> String {
    let key = String::from(start_key);

    let parsed_value: String = match str.find(&key) {
        Some(start_pos) => {
            let start = start_pos + key.len();
            let end_pos = str[start..].find(&end_key).unwrap();
            str[start..start + end_pos].to_string()
        }
        err => {
            println!("error parsing value from transcript");
            println!("{:?}", err);
            "".to_string()
            //panic()! uncomment in production
        }
    };
    parsed_value
}

#[cfg(feature = "tracing")]
mod test {
    use super::*;

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
        let (signature, signature_ethereum) = signer.sign(message.clone());

        #[cfg(feature = "tracing")]
        println!("message {}", message);

        println!("signature 0x{}", signature_ethereum);
    }

    #[test]
    #[cfg(feature = "tracing")]
    fn test_parse() {
        let json_str = String::from(
            r#"
        {
            "name": "John Doe",
            "age": 30,
            "email": "john.doe@example.com"
        }
    "#,
        );

        let start_key = String::from("name\": \"");
        let end_key = String::from("\"");

        let parsed_value: String = parse_value(json_str, start_key, end_key);
        println!("parsed_value: {}", parsed_value);
        assert!(parsed_value == "John Doe")
    }

    #[test]
    #[cfg(feature = "tracing")]
    fn test_parse_2() {
        let json_str = String::from(
            r#"
"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nDate: Fri, 14 Jun 2024 02:51:49 GMT\r\nTransfer-Encoding: chunked\r\nX-Frame-Options: SAMEORIGIN\r\nStrict-Transport-Security: max-age=63072000; includeSubDomains; preload\r\nContent-Security-Policy: object-src 'none'; script-src 'nonce-ZUToT69xQ40F4JPtCyvLZw==' 'report-sample' 'unsafe-inline' 'unsafe-eval' 'strict-dynamic' https: http:; base-uri 'none'; report-uri https://csp.withgoogle.com/csp/kaggle/20201130; frame-src 'self' https://www.kaggleusercontent.com https://www.youtube.com/embed/ https://polygraph-cool.github.io https://www.google.com/recaptcha/ https://www.docdroid.com https://www.docdroid.net https://kaggle-static.storage.googleapis.com https://kkb-production.jupyter-proxy.kaggle.net https://kkb-production.firebaseapp.com https://kaggle-metastore.firebaseapp.com https://apis.google.com https://content-sheets.googleapis.com/ https://accounts.google.com/ https://storage.googleapis.com https://docs.google.com https://drive.google.com https://calendar.google.com/;\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nVia: 1.1 google\r\nAlt-Svc: h3=\":443\"; ma=2592000,h3-29=\":443\"; ma=2592000\r\nConnection: close\r\n\r\n192\r\n{\"id\":21142885,\"displayName\":\"Zlim93200\",\"email\":\"batchtrain@gmail.com\",\"userName\":\"zlim93200\",\"thumbnailUrl\":\"https://storage.googleapis.com/kaggle-avatars/thumbnails/default-thumb.png\",\"profileUrl\":\"/zlim93200\",\"registerDate\":\"2024-06-04T16:22:44.700Z\",\"lastVisitDate\":\"2024-06-14T02:36:09.207Z\",\"statusId\":2,\"canAct\":true,\"canBeSeen\":true,\"thumbnailName\":\"default-thumb.png\",\"httpAcceptLanguage\":\"\"}\r\n0\r\n\r\n"
"#,
        );

        // \"userName\":\"zlim93200\"
        let start_key = String::from("userName\\\":\\\"");
        let end_key = String::from("\\\",");

        let parsed_value: String = parse_value(json_str, start_key, end_key);

        println!("parsed_value: {}", parsed_value);
        assert!(parsed_value == "zlim93200")
    }
}
