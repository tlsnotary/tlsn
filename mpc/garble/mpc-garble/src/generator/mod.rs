//! An implementation of a garbled circuit generator.

mod config;
mod error;

use std::{
    collections::HashSet,
    ops::DerefMut,
    sync::{Arc, Mutex},
};

use futures::{Sink, SinkExt};
use mpc_circuits::{types::ValueType, Circuit};
use mpc_core::hash::Hash;
use mpc_garble_core::{
    encoding_state, msg::GarbleMessage, ChaChaEncoder, EncodedValue, Encoder,
    Generator as GeneratorCore,
};
use utils_aio::non_blocking_backend::{Backend, NonBlockingBackend};

use crate::{
    config::{ValueConfig, ValueIdConfig},
    ot::OTSendEncoding,
    registry::EncodingRegistry,
    ValueId, ValueRef,
};

pub use config::{GeneratorConfig, GeneratorConfigBuilder};
pub use error::GeneratorError;

/// A garbled circuit generator.
#[derive(Debug, Default)]
pub struct Generator {
    config: GeneratorConfig,
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    /// The encoder used to encode values
    encoder: ChaChaEncoder,
    /// Encodings of values
    encoding_registry: EncodingRegistry<encoding_state::Full>,
    /// The set of values that are currently active.
    ///
    /// This is used to guarantee that the same encoding is never used
    /// with different active values.
    active: HashSet<ValueId>,
}

impl Generator {
    pub(crate) fn new(config: GeneratorConfig, encoder_seed: [u8; 32]) -> Self {
        Self {
            config,
            state: Mutex::new(State::new(ChaChaEncoder::new(encoder_seed))),
        }
    }

    /// Convenience method for grabbing a lock to the state.
    fn state(&self) -> impl DerefMut<Target = State> + '_ {
        self.state.lock().unwrap()
    }

    /// Returns the seed used to generate encodings.
    pub(crate) fn seed(&self) -> Vec<u8> {
        self.state().encoder.seed()
    }

    /// Returns the encoding for a value.
    pub(crate) fn get_encoding(
        &self,
        value: &ValueRef,
    ) -> Option<EncodedValue<encoding_state::Full>> {
        self.state().encoding_registry.get_encoding(value)
    }

    pub(crate) fn get_encodings_by_id(
        &self,
        ids: &[ValueId],
    ) -> Option<Vec<EncodedValue<encoding_state::Full>>> {
        let state = self.state();

        ids.iter()
            .map(|id| state.encoding_registry.get_encoding_by_id(id))
            .collect::<Option<Vec<_>>>()
    }

    /// Generate encodings for a slice of values
    pub(crate) fn generate_encodings(
        &self,
        values: &[(ValueId, ValueType)],
    ) -> Result<(), GeneratorError> {
        let mut state = self.state();

        for (id, ty) in values {
            _ = state.encode(id, ty)?;
        }

        Ok(())
    }

    /// Setup input values by transferring the encodings to the evaluator
    /// either directly or via oblivious transfer.
    ///
    /// # Arguments
    ///
    /// * `id` - The ID of this operation
    /// * `input_configs` - The inputs to set up
    /// * `sink` - The sink to send the encodings to the evaluator
    /// * `ot` - The OT sender.
    pub async fn setup_inputs<
        S: Sink<GarbleMessage, Error = std::io::Error> + Unpin,
        OT: OTSendEncoding,
    >(
        &self,
        id: &str,
        input_configs: &[ValueConfig],
        sink: &mut S,
        ot: &OT,
    ) -> Result<(), GeneratorError> {
        let (ot_send_values, direct_send_values) = {
            let mut state = self.state();

            // Filter out any values that are already active, setting them active otherwise.
            let mut input_configs: Vec<ValueIdConfig> = input_configs
                .iter()
                .flat_map(|config| config.clone().flatten())
                .filter(|config| state.active.insert(config.id().clone()))
                .collect();

            input_configs.sort_by_key(|config| config.id().clone());

            let mut ot_send_values = Vec::new();
            let mut direct_send_values = Vec::new();
            for config in input_configs.into_iter() {
                let encoding = state.encode(config.id(), config.value_type())?;

                match config {
                    ValueIdConfig::Public { value, .. } => {
                        direct_send_values.push(encoding.select(value)?);
                    }
                    ValueIdConfig::Private { value, .. } => {
                        if let Some(value) = value {
                            direct_send_values.push(encoding.select(value)?);
                        } else {
                            ot_send_values.push(encoding);
                        }
                    }
                }
            }

            (ot_send_values, direct_send_values)
        };

        let ot_fut = async {
            if !ot_send_values.is_empty() {
                ot.send(id, ot_send_values)
                    .await
                    .map_err(GeneratorError::from)
            } else {
                Ok(())
            }
        };

        let send_fut = async {
            if !direct_send_values.is_empty() {
                sink.send(GarbleMessage::ActiveValues(direct_send_values))
                    .await
                    .map_err(GeneratorError::from)
            } else {
                Ok(())
            }
        };

        futures::try_join!(ot_fut, send_fut)?;

        Ok(())
    }

    /// Generate a garbled circuit, streaming the encrypted gates to the evaluator in batches.
    ///
    /// Returns the encodings of the outputs, and optionally a hash of the circuit.
    ///
    /// # Arguments
    ///
    /// * `circ` - The circuit to garble
    /// * `inputs` - The inputs of the circuit
    /// * `outputs` - The outputs of the circuit
    /// * `sink` - The sink to send the garbled circuit to the evaluator
    /// * `hash` - Whether to hash the circuit
    pub async fn generate<S: Sink<GarbleMessage, Error = std::io::Error> + Unpin>(
        &self,
        circ: Arc<Circuit>,
        inputs: &[ValueRef],
        outputs: &[ValueRef],
        sink: &mut S,
        hash: bool,
    ) -> Result<(Vec<EncodedValue<encoding_state::Full>>, Option<Hash>), GeneratorError> {
        let (delta, inputs) = {
            let state = self.state();
            let delta = state.encoder.delta();
            let inputs = inputs
                .iter()
                .map(|value| {
                    state
                        .encoding_registry
                        .get_encoding(value)
                        .ok_or(GeneratorError::MissingEncoding(value.clone()))
                })
                .collect::<Result<Vec<_>, _>>()?;

            (delta, inputs)
        };

        let mut gen = if hash {
            GeneratorCore::new_with_hasher(circ.clone(), delta, &inputs)?
        } else {
            GeneratorCore::new(circ.clone(), delta, &inputs)?
        };

        let mut batch: Vec<_>;
        let batch_size = self.config.batch_size;
        while !gen.is_complete() {
            // Move the generator to another thread to produce the next batch
            // then send it back
            (gen, batch) = Backend::spawn(move || {
                let batch = gen.by_ref().take(batch_size).collect();
                (gen, batch)
            })
            .await;

            if !batch.is_empty() {
                sink.send(GarbleMessage::EncryptedGates(batch)).await?;
            }
        }

        let encoded_outputs = gen.outputs()?;
        let hash = gen.hash();

        if self.config.encoding_commitments {
            let commitments = encoded_outputs
                .iter()
                .map(|output| output.commit())
                .collect();

            sink.send(GarbleMessage::EncodingCommitments(commitments))
                .await?;
        }

        // Add the outputs to the encoding registry and set as active.
        let mut state = self.state();
        for (output, encoding) in outputs.iter().zip(encoded_outputs.iter()) {
            state
                .encoding_registry
                .set_encoding(output, encoding.clone())?;
            output.iter().for_each(|id| {
                state.active.insert(id.clone());
            });
        }

        Ok((encoded_outputs, hash))
    }

    /// Send value decoding information to the evaluator.
    ///
    /// # Arguments
    ///
    /// * `values` - The values to decode
    /// * `sink` - The sink to send the decodings with
    pub async fn decode<S: Sink<GarbleMessage, Error = std::io::Error> + Unpin>(
        &self,
        values: &[ValueRef],
        sink: &mut S,
    ) -> Result<(), GeneratorError> {
        let decodings = {
            let state = self.state();
            values
                .iter()
                .map(|value| {
                    state
                        .encoding_registry
                        .get_encoding(value)
                        .ok_or(GeneratorError::MissingEncoding(value.clone()))
                        .map(|encoding| encoding.decoding())
                })
                .collect::<Result<Vec<_>, _>>()?
        };

        sink.send(GarbleMessage::ValueDecodings(decodings)).await?;

        Ok(())
    }
}

impl State {
    fn new(encoder: ChaChaEncoder) -> Self {
        Self {
            encoder,
            ..Default::default()
        }
    }

    fn encode(
        &mut self,
        id: &ValueId,
        ty: &ValueType,
    ) -> Result<EncodedValue<encoding_state::Full>, GeneratorError> {
        let encoding = self.encoder.encode_by_type(id.encoding_id().to_inner(), ty);

        // Returns error if the encoding already exists
        self.encoding_registry
            .set_encoding_by_id(id, encoding.clone())?;

        Ok(encoding)
    }
}
