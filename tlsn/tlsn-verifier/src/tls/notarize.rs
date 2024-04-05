//! This module handles the notarization phase of the verifier.
//!
//! The TLS verifier is only a notary.

use futures::{FutureExt, SinkExt, StreamExt, TryFutureExt};
use mpz_share_conversion::ShareConversionVerify;
use rand::{thread_rng, Rng};
use signature::Signer;
use tls_mpc::MpcTlsFollowerData;
use tlsn_common::{
    attestation::{AttestationRequest, SignedAttestation},
    msg::TlsnMessage,
};
use tlsn_core::{
    attestation::{
        Attestation, AttestationBodyBuilder, AttestationHeader, Field, ATTESTATION_VERSION,
    },
    conn::{
        ConnectionInfo, HandshakeData, HandshakeDataV1_2, KeyType, ServerEphemKey, TlsVersion,
        TranscriptLength,
    },
    encoding::EncodingCommitment,
    Signature,
};
use utils_aio::{expect_msg_or_err, mux::MuxChannel};

use crate::tls::{config::MAX_TIME_DIFF, state::Notarize, Verifier, VerifierError};

#[cfg(feature = "tracing")]
use tracing::info;

impl Verifier<Notarize> {
    /// Notarizes the TLS session.
    pub async fn finalize<T>(self, signer: &impl Signer<T>) -> Result<Attestation, VerifierError>
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
            mpc_tls_data,
        } = self.state;

        let notarize_fut = async {
            let mut notarize_channel = mux_ctrl.get_channel("notarize").await?;

            let AttestationRequest {
                hash_alg,
                time,
                cert_commitment,
                cert_chain_commitment,
                encoding_commitment_root,
                ..
            } = expect_msg_or_err!(notarize_channel, TlsnMessage::AttestationRequest)?;

            // Make sure the requested time is within the allowed time difference
            if time.abs_diff(start_time) > MAX_TIME_DIFF {
                todo!()
            }

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

            let (info, hs_data) = convert_mpc_tls_data(mpc_tls_data, time);

            let mut attestation_body_builder = AttestationBodyBuilder::default();
            attestation_body_builder
                .field(Field::ConnectionInfo(info))
                .unwrap()
                .field(Field::HandshakeData(hs_data))
                .unwrap()
                .field(Field::CertificateCommitment(cert_commitment))
                .unwrap()
                .field(Field::CertificateChainCommitment(cert_chain_commitment))
                .unwrap();

            if let Some(root) = encoding_commitment_root {
                attestation_body_builder
                    .field(Field::EncodingCommitment(EncodingCommitment {
                        root,
                        seed: encoder_seed.to_vec(),
                    }))
                    .unwrap();
            }

            let attestation_body = attestation_body_builder.build().unwrap();
            let attestation_header = AttestationHeader {
                id: thread_rng().gen::<[u8; 16]>().into(),
                version: ATTESTATION_VERSION.clone(),
                root: attestation_body.root(hash_alg),
            };

            let sig: Signature = signer.sign(&attestation_header.serialize()).into();

            #[cfg(feature = "tracing")]
            info!("Signed attestation");

            notarize_channel
                .send(TlsnMessage::SignedAttestation(SignedAttestation {
                    sig: sig.clone(),
                    header: attestation_header.clone(),
                }))
                .await?;

            #[cfg(feature = "tracing")]
            info!("Sent attestation");

            Ok::<_, VerifierError>(Attestation {
                sig,
                header: attestation_header,
                body: attestation_body,
            })
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

fn convert_mpc_tls_data(data: MpcTlsFollowerData, time: u64) -> (ConnectionInfo, HandshakeData) {
    (
        ConnectionInfo {
            time,
            version: TlsVersion::V1_2,
            transcript_length: TranscriptLength {
                sent: data.bytes_sent as u32,
                received: data.bytes_recv as u32,
            },
        },
        HandshakeData::V1_2(HandshakeDataV1_2 {
            client_random: data.client_random,
            server_random: data.server_random,
            server_ephemeral_key: ServerEphemKey {
                typ: KeyType::Secp256r1,
                key: data.server_key.key,
            },
        }),
    )
}
