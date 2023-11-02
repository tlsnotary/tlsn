//! This module handles the verification phase of the prover.
//!
//! Here the prover deals with a TLS verifier that is a notary and a verifier.

use super::{state::Verify, Prover, ProverError};
use crate::tls::error::OTShutdownError;
use futures::{FutureExt, SinkExt};
use mpz_garble::{value::ValueRef, Decode, Memory, Vm};
use mpz_share_conversion::ShareConversionReveal;
use tlsn_core::{msg::TlsnMessage, Direction, ServerName, SessionData, Transcript};
use utils::range::RangeSet;
use utils_aio::mux::MuxChannel;

impl Prover<Verify> {
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
    /// This function allows to collect certain transcript ranges. When [Prover::decode] is called, these
    /// ranges will be opened to the verifier.
    ///
    /// # Arguments
    /// * `ranges` - The ranges of the transcript to reveal
    /// * `direction` - The direction of the transcript to reveal
    pub fn reveal(
        &mut self,
        ranges: impl Into<RangeSet<usize>>,
        direction: Direction,
    ) -> Result<(), ProverError> {
        self.state
            .proof
            .reveal_ranges(ranges.into(), direction)
            .map_err(ProverError::from)
    }

    /// Decodes transcript values
    pub async fn decode(&mut self) -> Result<(), ProverError> {
        let transcript_proof = std::mem::take(&mut self.state.proof);

        let mut verify_fut = Box::pin(async {
            let channel = if let Some(ref mut channel) = self.state.channel {
                channel
            } else {
                self.state.channel = Some(self.state.verify_mux.get_channel("verify").await?);
                self.state.channel.as_mut().unwrap()
            };

            let decode_thread = if let Some(ref mut decode_thread) = self.state.decode_thread {
                decode_thread
            } else {
                self.state.decode_thread = Some(self.state.vm.new_thread("decode").await?);
                self.state.decode_thread.as_mut().unwrap()
            };

            // Get the decoded value refs from the DEAP vm
            let value_refs = transcript_proof
                .iter_ids("tx", "rx")
                .map(|id| {
                    decode_thread
                        .get_value(id.as_str())
                        .ok_or(ProverError::from(
                            "Transcript value cannot be decoded from VM thread",
                        ))
                })
                .collect::<Result<Vec<ValueRef>, ProverError>>()?;

            // Send the ids to the verifier so that he can also create the corresponding value refs
            channel
                .send(TlsnMessage::DecodingInfo(transcript_proof.into()))
                .await?;

            // Decode the corresponding values
            let values = decode_thread.decode(value_refs.as_slice()).await?;
            Ok::<_, ProverError>(values)
        })
        .fuse();

        let _ = futures::select_biased! {
            res = verify_fut => res?,
            _ = &mut self.state.ot_fut => return Err(OTShutdownError)?,
            _ = &mut self.state.mux_fut => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?,
        };

        Ok(())
    }

    /// Finalize the verification
    pub async fn finalize(self) -> Result<SessionData, ProverError> {
        let Verify {
            mut verify_mux,
            mut mux_fut,
            mut vm,
            mut ot_fut,
            mut gf2,
            handshake_decommitment,
            transcript_tx,
            transcript_rx,
            ..
        } = self.state;

        // Create session data and session_info
        let session_data = SessionData::new(
            ServerName::Dns(self.config.server_dns().to_string()),
            handshake_decommitment,
            transcript_tx,
            transcript_rx,
        );
        let session_info = session_data.session_info().clone();

        let mut verify_fut = Box::pin(async move {
            let mut channel = verify_mux.get_channel("finalize").await?;

            // This is a temporary approach until a maliciously secure share conversion protocol is implemented.
            // The prover is essentially revealing the TLS MAC key. In some exotic scenarios this allows a malicious
            // TLS verifier to modify the prover's request.
            gf2.reveal()
                .await
                .map_err(|e| ProverError::MpcError(Box::new(e)))?;

            _ = vm
                .finalize()
                .await
                .map_err(|e| ProverError::MpcError(Box::new(e)))?
                .expect("encoder seed returned");

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

        Ok(session_data)
    }
}
