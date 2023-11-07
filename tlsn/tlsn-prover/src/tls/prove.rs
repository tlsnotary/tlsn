//! This module handles the proving phase of the prover.
//!
//! Here the prover deals with a TLS verifier that is a notary and a verifier.

use super::{state::Prove as ProveState, Prover, ProverError};
use crate::tls::error::OTShutdownError;
use futures::{FutureExt, SinkExt};
use mpz_garble::{Memory, Prove, Vm};
use mpz_share_conversion::ShareConversionReveal;
use tlsn_core::{
    msg::TlsnMessage, proof::SessionInfo, transcript::get_value_ids, Direction, ServerName,
    Transcript,
};
use utils::range::{RangeSet, RangeUnion};
use utils_aio::mux::MuxChannel;

#[cfg(feature = "tracing")]
use tracing::info;

impl Prover<ProveState> {
    /// Returns the transcript of the sent requests
    pub fn sent_transcript(&self) -> &Transcript {
        &self.state.transcript_tx
    }

    /// Returns the transcript of the received responses
    pub fn recv_transcript(&self) -> &Transcript {
        &self.state.transcript_rx
    }

    /// Reveal certain parts of the transcripts to the verifier
    ///
    /// This function allows to collect certain transcript ranges. When [Prover::prove] is called, these
    /// ranges will be opened to the verifier.
    ///
    /// # Arguments
    /// * `ranges` - The ranges of the transcript to reveal
    /// * `direction` - The direction of the transcript to reveal
    pub fn reveal(&mut self, ranges: impl Into<RangeSet<usize>>, direction: Direction) {
        let sent_ids = &mut self.state.proving_info.sent_ids;
        let recv_ids = &mut self.state.proving_info.recv_ids;

        match direction {
            Direction::Sent => *sent_ids = sent_ids.union(&ranges.into()),
            Direction::Received => *recv_ids = recv_ids.union(&ranges.into()),
        }
    }

    /// Prove transcript values
    pub async fn prove(&mut self) -> Result<(), ProverError> {
        let mut proving_info = std::mem::take(&mut self.state.proving_info);

        // Check ranges
        if proving_info.sent_ids.max().unwrap_or_default() > self.state.transcript_tx.data().len()
            || proving_info.recv_ids.max().unwrap_or_default()
                > self.state.transcript_rx.data().len()
        {
            return Err(ProverError::from(
                "Proving information contains ids which exceed transcript length",
            ));
        }

        let mut prove_fut = Box::pin(async {
            // Create a new channel and vm thread if not already present
            let channel = if let Some(ref mut channel) = self.state.channel {
                channel
            } else {
                self.state.channel = Some(self.state.verify_mux.get_channel("prove-verify").await?);
                self.state.channel.as_mut().unwrap()
            };

            let prove_thread = if let Some(ref mut prove_thread) = self.state.prove_thread {
                prove_thread
            } else {
                self.state.prove_thread = Some(self.state.vm.new_thread("prove-verify").await?);
                self.state.prove_thread.as_mut().unwrap()
            };

            // Now prove the transcript parts which have been marked for reveal
            let sent_value_ids = proving_info
                .sent_ids
                .iter_ranges()
                .map(|r| get_value_ids(&r.into(), Direction::Sent).collect::<Vec<String>>());
            let recv_value_ids = proving_info
                .recv_ids
                .iter_ranges()
                .map(|r| get_value_ids(&r.into(), Direction::Received).collect::<Vec<String>>());

            let value_refs = sent_value_ids
                .chain(recv_value_ids)
                .map(|ids| {
                    let inner_refs = ids
                        .iter()
                        .map(|id| {
                            prove_thread
                                .get_value(id.as_str())
                                .expect("Byte should be in VM memory")
                        })
                        .collect::<Vec<_>>();

                    prove_thread
                        .array_from_values(inner_refs.as_slice())
                        .expect("Byte should be in VM Memory")
                })
                .collect::<Vec<_>>();

            // Extract cleartext we want to reveal from transcripts
            let mut cleartext = vec![];
            proving_info
                .sent_ids
                .iter_ranges()
                .for_each(|r| cleartext.extend_from_slice(&self.state.transcript_tx.data()[r]));
            proving_info
                .recv_ids
                .iter_ranges()
                .for_each(|r| cleartext.extend_from_slice(&self.state.transcript_rx.data()[r]));
            proving_info.cleartext = cleartext;

            // Send the proving info to the verifier
            channel.send(TlsnMessage::ProvingInfo(proving_info)).await?;

            #[cfg(feature = "tracing")]
            info!("Sent proving info to verifier");

            // Prove the revealed transcript parts
            prove_thread.prove(value_refs.as_slice()).await?;

            #[cfg(feature = "tracing")]
            info!("Successfully proved cleartext");

            Ok::<_, ProverError>(())
        })
        .fuse();

        futures::select_biased! {
            res = prove_fut => res?,
            _ = &mut self.state.ot_fut => return Err(OTShutdownError)?,
            _ = &mut self.state.mux_fut => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?,
        };

        Ok(())
    }

    /// Finalize the proving
    pub async fn finalize(self) -> Result<(), ProverError> {
        let ProveState {
            mut verify_mux,
            mut mux_fut,
            mut vm,
            mut ot_fut,
            mut gf2,
            handshake_decommitment,
            ..
        } = self.state;

        // Create session data and session_info
        let session_info = SessionInfo {
            server_name: ServerName::Dns(self.config.server_dns().to_string()),
            handshake_decommitment,
        };

        let mut verify_fut = Box::pin(async move {
            let mut channel = verify_mux.get_channel("finalize").await?;

            _ = vm
                .finalize()
                .await
                .map_err(|e| ProverError::MpcError(Box::new(e)))?
                .expect("encoder seed returned");

            // This is a temporary approach until a maliciously secure share conversion protocol is implemented.
            // The prover is essentially revealing the TLS MAC key. In some exotic scenarios this allows a malicious
            // TLS verifier to modify the prover's request.
            gf2.reveal()
                .await
                .map_err(|e| ProverError::MpcError(Box::new(e)))?;

            // Send session_info to the verifier
            channel.send(TlsnMessage::SessionInfo(session_info)).await?;

            Ok::<_, ProverError>(())
        })
        .fuse();

        futures::select_biased! {
            res = verify_fut => res?,
            _ = ot_fut => return Err(OTShutdownError)?,
            _ = mux_fut => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?,
        };

        Ok(())
    }
}
