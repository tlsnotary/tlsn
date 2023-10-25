//! This module handles the verification phase of the verifier.
//!
//! The TLS verifier is an application-specific verifier.

use super::{state::Verify, Verifier, VerifierError};
use futures::{FutureExt, SinkExt, StreamExt, TryFutureExt};
use mpz_share_conversion::ShareConversionVerify;
use tlsn_core::{msg::TlsnMessage, HandshakeSummary, SessionHeader};
use utils_aio::{expect_msg_or_err, mux::MuxChannel};

#[cfg(feature = "tracing")]
use tracing::info;

impl Verifier<Verify> {
    /// Verify the TLS session.
    pub async fn finalize(self) -> Result<(), VerifierError> {
        let Verify {
            mut mux,
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

        let verify_fut = async {
            //let mut verify_channel = mux.get_channel("verify").await?;

            // TODO: Do deap vm decoding here
            // Probably need the `ValueRefs` first from prover
            // Then call vm decode

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

            Ok::<_, VerifierError>(())
        };

        let values = futures::select! {
            res = verify_fut.fuse() => res?,
            _ = &mut mux_fut => Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?,
        };
        // TODO: What do we return here for the verifier?

        let mut mux = mux.into_inner();

        futures::try_join!(mux.close().map_err(VerifierError::from), mux_fut)?;

        todo!()
    }
}
