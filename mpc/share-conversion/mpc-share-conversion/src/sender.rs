//! This module implements the Sender for the share conversion protocol.

use std::sync::Mutex;

use futures::{Sink, SinkExt};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use mpc_share_conversion_core::{
    fields::Field,
    msgs::{SenderRecordings, ShareConversionMessage},
    Share,
};

use crate::{ot::OTSendElement, tape::SenderTape, SenderConfig, ShareConversionError};

/// The share conversion sender
#[derive(Debug)]
pub struct GilboaSender<F>
where
    F: Field,
{
    config: SenderConfig,
    state: Mutex<State<F>>,
}

pub(crate) struct State<F: Field> {
    rng: ChaCha20Rng,
    pub(crate) tape: Option<SenderTape<F>>,
    /// keeps track of how many batched share conversions we've made so far
    counter: usize,
    finalized: bool,
}

impl<F: Field> std::fmt::Debug for State<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "State {{ .. }}")
    }
}

impl<F> GilboaSender<F>
where
    F: Field,
{
    /// Create a new sender
    pub fn new(config: SenderConfig) -> Self {
        let rng = ChaCha20Rng::from_entropy();
        let tape = config.record().then(SenderTape::default);

        Self {
            config,
            state: Mutex::new(State {
                rng,
                tape,
                counter: 0,
                finalized: false,
            }),
        }
    }

    /// Converts a batch of shares using oblivious transfer
    ///
    /// # Arguments
    ///
    /// * `ot` - OT sender
    /// * `shares` - field element shares
    pub async fn convert_from<OT: OTSendElement<F>>(
        &self,
        ot: &OT,
        shares: &[Share<F>],
    ) -> Result<Vec<Share<F>>, ShareConversionError> {
        if shares.is_empty() {
            return Ok(vec![]);
        }

        let (new_shares, summands, ot_id) = {
            let mut state = self.state.lock().unwrap();

            if state.finalized {
                return Err(ShareConversionError::AlreadyFinalized);
            }

            if let Some(tape) = state.tape.as_mut() {
                tape.record(shares);
            }

            let ot_id = format!("{}/{}", &self.config.id(), state.counter);
            state.counter += 1;

            let mut new_shares: Vec<Share<F>> = Vec::with_capacity(shares.len());
            let mut all_summands = Vec::with_capacity(shares.len() * F::BIT_SIZE as usize);
            for share in shares {
                let (new_share, summands) = share.convert(&mut state.rng);
                new_shares.push(new_share);
                all_summands.extend(summands);
            }

            (new_shares, all_summands, ot_id)
        };

        // Send OT shares to the receiver
        ot.send(&ot_id, summands).await?;

        Ok(new_shares)
    }

    /// Reveals the Sender's RNG seed and tape to the Receiver.
    pub async fn reveal<S: Sink<ShareConversionMessage<F>, Error = std::io::Error> + Unpin>(
        &mut self,
        sink: &mut S,
    ) -> Result<(), ShareConversionError> {
        let message = {
            let mut state = self.state.lock().unwrap();

            if state.finalized {
                return Err(ShareConversionError::AlreadyFinalized);
            } else {
                state.finalized = true;
            }

            let Some(tape) = state.tape.take() else {
                return Err(ShareConversionError::TapeNotConfigured);
            };

            SenderRecordings {
                seed: state.rng.get_seed().to_vec(),
                inputs: tape.inputs,
            }
        };

        sink.send(ShareConversionMessage::SenderRecordings(message))
            .await?;

        Ok(())
    }
}

#[cfg(test)]
use std::ops::DerefMut;

// Used for unit testing
#[cfg(test)]
impl<F> GilboaSender<F>
where
    F: Field,
{
    pub(crate) fn state_mut(&mut self) -> impl DerefMut<Target = State<F>> + '_ {
        self.state.try_lock().unwrap()
    }
}
