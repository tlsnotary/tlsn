//! This module handles the verification phase of the verifier.
//!
//! The TLS verifier is an application-specific verifier.

use super::{state::Verify, Verifier, VerifierError};
use futures::{FutureExt, StreamExt, TryFutureExt};
use mpz_garble::{Decode, Memory, Vm};
use mpz_share_conversion::ShareConversionVerify;
use tlsn_core::{
    msg::TlsnMessage, proof::SessionInfo, transcript::get_value_ids, Direction, HandshakeSummary,
    RedactedTranscript, TranscriptSlice,
};
use utils_aio::{expect_msg_or_err, mux::MuxChannel};

#[cfg(feature = "tracing")]
use tracing::info;

impl Verifier<Verify> {
    /// Receives the **purported** transcript from the Prover.
    ///
    /// # Warning
    ///
    /// The content of the received transcripts can not be considered authentic until after finalization.
    pub async fn receive(
        &mut self,
    ) -> Result<(RedactedTranscript, RedactedTranscript), VerifierError> {
        let verify_fut = async {
            let channel = if let Some(ref mut channel) = self.state.channel {
                channel
            } else {
                self.state.channel = Some(self.state.mux.get_channel("verify").await?);
                self.state.channel.as_mut().unwrap()
            };

            let decode_thread = if let Some(ref mut decode_thread) = self.state.decode_thread {
                decode_thread
            } else {
                self.state.decode_thread = Some(self.state.vm.new_thread("decode").await?);
                self.state.decode_thread.as_mut().unwrap()
            };

            let decoding_info = expect_msg_or_err!(channel, TlsnMessage::DecodingInfo)?;

            let send_value_ids = decoding_info
                .sent_ids
                .iter_ranges()
                .map(|r| get_value_ids(&r.into(), Direction::Sent).collect::<Vec<String>>());
            let recv_value_ids = decoding_info
                .recv_ids
                .iter_ranges()
                .map(|r| get_value_ids(&r.into(), Direction::Received).collect::<Vec<String>>());

            let value_refs = send_value_ids
                .chain(recv_value_ids)
                .map(|ids| {
                    let inner_refs = ids
                        .iter()
                        .map(|id| {
                            decode_thread
                                .get_value(id.as_str())
                                .ok_or(VerifierError::from(
                                    "Transcript value cannot be decoded from VM thread",
                                ))
                        })
                        .collect::<Result<Vec<_>, _>>()
                        .expect("Should be able to collect");
                    decode_thread.array_from_values(inner_refs.as_slice())
                })
                .collect::<Result<Vec<_>, _>>()?;

            let values = decode_thread
                .decode(value_refs.as_slice())
                .await?
                .into_iter()
                .map(|v| v.try_into())
                .collect::<Result<Vec<Vec<u8>>, _>>()
                .map_err(|err| {
                    VerifierError::from(
                        format!("Error converting decoded values: {}", err).as_str(),
                    )
                })?;

            let mut transcripts = decoding_info
                .sent_ids
                .iter_ranges()
                .chain(decoding_info.recv_ids.iter_ranges())
                .zip(values.into_iter())
                .map(|(range, data)| TranscriptSlice::new(range, data))
                .collect::<Vec<_>>();

            let recv_transcripts =
                transcripts.split_off(decoding_info.sent_ids.iter_ranges().count());
            let (sent_redacted, recv_redacted) = (
                RedactedTranscript::new(self.state.sent_len, transcripts),
                RedactedTranscript::new(self.state.recv_len, recv_transcripts),
            );

            #[cfg(feature = "tracing")]
            info!("Successfully decoded transcript parts");

            Ok::<_, VerifierError>((sent_redacted, recv_redacted))
        };

        futures::select! {
            res = verify_fut.fuse() => res,
            _ = &mut self.state.mux_fut => Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?,
        }
    }

    /// Verify the TLS session.
    pub async fn finalize(self) -> Result<SessionInfo, VerifierError> {
        let Verify {
            mut mux,
            mut mux_fut,
            mut vm,
            ot_send,
            ot_recv,
            ot_fut,
            mut gf2,
            start_time,
            server_ephemeral_key,
            handshake_commitment,
            ..
        } = self.state;

        let finalize_fut = async {
            let mut channel = mux.get_channel("finalize").await?;

            // Finalize all MPC
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

            let session_info = expect_msg_or_err!(channel, TlsnMessage::SessionInfo)?;

            #[cfg(feature = "tracing")]
            info!("Finalized all MPC");

            Ok::<_, VerifierError>(session_info)
        };

        let session_info = futures::select! {
            res = finalize_fut.fuse() => res?,
            _ = &mut mux_fut => Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?,
        };

        let handshake_summary =
            HandshakeSummary::new(start_time, server_ephemeral_key, handshake_commitment);

        // Verify the TLS session
        session_info.verify(&handshake_summary, self.config.cert_verifier())?;

        #[cfg(feature = "tracing")]
        info!("Successfully verified session");

        let mut mux = mux.into_inner();

        futures::try_join!(mux.close().map_err(VerifierError::from), mux_fut)?;

        Ok(session_info)
    }
}
