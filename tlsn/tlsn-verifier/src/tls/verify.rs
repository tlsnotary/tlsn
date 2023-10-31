//! This module handles the verification phase of the verifier.
//!
//! The TLS verifier is an application-specific verifier.

use super::{state::Verify, Verifier, VerifierError};
use futures::{FutureExt, StreamExt, TryFutureExt};
use mpz_garble::{value::ValueRef, Decode, Memory, Vm};
use mpz_share_conversion::ShareConversionVerify;
use tlsn_core::{
    msg::TlsnMessage,
    proof::{substring::LabelProof, SubstringProofError},
    HandshakeSummary, RedactedTranscript,
};
use utils_aio::{expect_msg_or_err, mux::MuxChannel};

#[cfg(feature = "tracing")]
use tracing::info;

impl Verifier<Verify> {
    /// Verify the TLS session.
    pub async fn finalize(self) -> Result<(RedactedTranscript, RedactedTranscript), VerifierError> {
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
            sent_len,
            recv_len,
        } = self.state;

        let verify_fut = async {
            let mut verify_channel = mux.get_channel("verify").await?;
            let decoding_info = expect_msg_or_err!(verify_channel, TlsnMessage::DecodingInfo)?;

            // Get the decoded value refs from the DEAP vm
            let mut decode_thread = vm.new_thread("decode").await?;
            let mut label_proof: LabelProof = decoding_info.into();

            // Get the decoded value refs from the DEAP vm
            let value_refs = label_proof
                .value_refs(|id| decode_thread.get_value(id.as_str()))
                .map(|value_ref| value_ref.ok_or(VerifierError::TranscriptDecodeError))
                .collect::<Result<Vec<ValueRef>, VerifierError>>()?;

            // Decode the corresponding values
            let values = decode_thread.decode(value_refs.as_slice()).await?;
            label_proof
                .set_decoding(values)
                .map_err(SubstringProofError::from)?;

            #[cfg(feature = "tracing")]
            info!("Successfully decoded transcript parts");

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

            let tls_info = expect_msg_or_err!(verify_channel, TlsnMessage::TlsInfo)?;

            #[cfg(feature = "tracing")]
            info!("Finalized all MPC");

            Ok::<_, VerifierError>((label_proof, tls_info))
        };

        let (label_proof, tls_info) = futures::select! {
            res = verify_fut.fuse() => res?,
            _ = &mut mux_fut => Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?,
        };

        let handshake_summary =
            HandshakeSummary::new(start_time, server_ephemeral_key, handshake_commitment);

        // Verify the TLS session
        tls_info
            .session_info
            .verify(&handshake_summary, self.config.cert_verifier())?;

        // Get the redacted transcripts
        let (redacted_sent, redacted_received) = label_proof
            .verify(sent_len, recv_len)
            .map_err(SubstringProofError::from)?;

        #[cfg(feature = "tracing")]
        info!("Successfully verified session and transcript lengths");

        let mut mux = mux.into_inner();

        futures::try_join!(mux.close().map_err(VerifierError::from), mux_fut)?;

        Ok((redacted_sent, redacted_received))
    }
}
