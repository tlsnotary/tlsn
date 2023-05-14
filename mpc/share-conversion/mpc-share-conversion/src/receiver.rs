//! This module implements the Receiver for the share conversion protocol.

use std::sync::Mutex;

use futures::{Stream, StreamExt};

use mpc_share_conversion_core::{
    fields::Field,
    msgs::{SenderRecordings, ShareConversionMessage},
    Share,
};

use crate::{ot::OTReceiveElement, tape::ReceiverTape, ReceiverConfig, ShareConversionError};

/// The share conversion receiver
#[derive(Debug)]
pub struct GilboaReceiver<F>
where
    F: Field,
{
    config: ReceiverConfig,
    state: Mutex<State<F>>,
}

struct State<F: Field> {
    tape: Option<ReceiverTape<F>>,
    /// keeps track of how many batched share conversions we've made so far
    counter: usize,
    finalized: bool,
}

impl<F: Field> std::fmt::Debug for State<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "State {{ .. }}")
    }
}

impl<F> GilboaReceiver<F>
where
    F: Field,
{
    /// Create a new receiver
    pub fn new(config: ReceiverConfig) -> Self {
        let tape = config.record().then(ReceiverTape::default);
        Self {
            config,
            state: Mutex::new(State {
                tape,
                counter: 0,
                finalized: false,
            }),
        }
    }

    /// Converts a batch of shares using oblivious transfer
    pub async fn convert_from<OT: OTReceiveElement<F>>(
        &self,
        ot: &OT,
        shares: &[Share<F>],
    ) -> Result<Vec<Share<F>>, ShareConversionError> {
        if shares.is_empty() {
            return Ok(vec![]);
        }

        let choices = shares
            .iter()
            .flat_map(|share| share.binary_encoding())
            .collect::<Vec<_>>();

        let ot_id = {
            let mut state = self.state.lock().unwrap();

            if state.finalized {
                return Err(ShareConversionError::AlreadyFinalized);
            }

            let ot_id = format!("{}/{}", &self.config.id(), state.counter);
            state.counter += 1;

            ot_id
        };

        // Receive OT shares from the sender and increment batch counter
        let summands = ot.receive(&ot_id, choices).await?;

        // Aggregate summands into shares
        let converted_shares: Vec<Share<F>> = summands
            .chunks(F::BIT_SIZE as usize)
            .zip(shares)
            .map(|(summands, share)| share.ty().other().new_from_summands(summands))
            .collect();

        if let Some(tape) = self.state.lock().unwrap().tape.as_mut() {
            tape.record(shares, &converted_shares);
        }

        Ok(converted_shares)
    }

    /// Receives the Sender's seed and tape and verifies them against the receiver's tape
    /// to detect malicious behavior.
    pub async fn verify<S: Stream<Item = ShareConversionMessage<F>> + Unpin>(
        &mut self,
        stream: &mut S,
    ) -> Result<(), ShareConversionError> {
        let tape = {
            let mut state = self.state.lock().unwrap();

            if state.finalized {
                return Err(ShareConversionError::AlreadyFinalized);
            } else {
                state.finalized = true;
            }

            state
                .tape
                .take()
                .ok_or(ShareConversionError::TapeNotConfigured)?
        };

        let message = stream
            .next()
            .await
            .ok_or(std::io::Error::from(std::io::ErrorKind::ConnectionAborted))?;

        let ShareConversionMessage::SenderRecordings(SenderRecordings {
            seed,
            inputs: sender_inputs,
        }) = message;

        let seed: [u8; 32] = seed
            .try_into()
            .map_err(|_| ShareConversionError::InvalidSeed)?;

        tape.verify(seed, &sender_inputs)?;

        Ok(())
    }
}
