//! An implementation of a garbled circuit evaluator.

mod config;
mod error;

use std::{
    collections::{HashMap, HashSet},
    ops::DerefMut,
    sync::{Arc, Mutex},
};

use futures::{stream::FuturesUnordered, SinkExt, Stream, StreamExt};
use mpc_circuits::{
    types::{TypeError, Value, ValueType},
    Circuit,
};
use mpc_core::{
    hash::Hash,
    value::{ValueId, ValueRef},
};
use mpc_garble_core::{
    encoding_state, msg::GarbleMessage, Decoding, EncodedValue, Evaluator as EvaluatorCore,
};
use utils::iter::FilterDrain;
use utils_aio::{
    expect_msg_or_err,
    non_blocking_backend::{Backend, NonBlockingBackend},
};

use crate::{
    config::ValueIdConfig,
    ot::{OTReceiveEncoding, OTVerifyEncoding},
    registry::EncodingRegistry,
    Generator, GeneratorConfigBuilder,
};

pub use config::{EvaluatorConfig, EvaluatorConfigBuilder};
pub use error::EvaluatorError;

use error::VerificationError;

/// A garbled circuit evaluator.
#[derive(Debug)]
pub struct Evaluator {
    config: EvaluatorConfig,
    state: Mutex<State>,
}

impl Default for Evaluator {
    fn default() -> Self {
        Self {
            config: EvaluatorConfigBuilder::default().build().unwrap(),
            state: Mutex::new(State::default()),
        }
    }
}

#[derive(Debug, Default)]
struct State {
    /// Encodings of values
    encoding_registry: EncodingRegistry<encoding_state::Active>,
    /// Encoded values which were received either directly or via OT
    received_values: HashMap<ValueId, ValueType>,
    /// Values which have been decoded
    decoded_values: HashSet<ValueId>,
    /// OT logs
    ot_log: HashMap<String, Vec<ValueId>>,
    /// Garbled circuit logs
    circuit_logs: Vec<EvaluatorLog>,
    /// Decodings of values received from the generator
    decoding_logs: HashMap<ValueRef, Decoding>,
}

impl Evaluator {
    /// Creates a new evaluator.
    pub fn new(config: EvaluatorConfig) -> Self {
        Self {
            config,
            ..Default::default()
        }
    }

    /// Convenience method for grabbing a lock to the state.
    fn state(&self) -> impl DerefMut<Target = State> + '_ {
        self.state.lock().unwrap()
    }

    /// Sets a value as decoded.
    ///
    /// # Errors
    ///
    /// Returns an error if the value has already been decoded.
    pub(crate) fn set_decoded(&self, value: &ValueRef) -> Result<(), EvaluatorError> {
        let mut state = self.state();
        // Check that none of the values in this reference have already been decoded.
        // We track every individual value of an array separately to ensure that a decoding
        // is never overwritten.
        for id in value.iter() {
            if !state.decoded_values.insert(id.clone()) {
                return Err(EvaluatorError::DuplicateDecoding(id.clone()));
            }
        }

        Ok(())
    }

    /// Returns the encoding for a value.
    pub fn get_encoding(&self, value: &ValueRef) -> Option<EncodedValue<encoding_state::Active>> {
        self.state().encoding_registry.get_encoding(value)
    }

    /// Adds a decoding log entry.
    pub(crate) fn add_decoding_log(&self, value: &ValueRef, decoding: Decoding) {
        self.state().decoding_logs.insert(value.clone(), decoding);
    }

    /// Setup input values by receiving the encodings from the generator
    /// either directly or via oblivious transfer.
    ///
    /// # Arguments
    ///
    /// * `id` - The id of this operation
    /// * `input_configs` - The inputs to setup
    /// * `stream` - The stream of messages from the generator
    /// * `ot` - The oblivious transfer receiver
    pub async fn setup_inputs<
        S: Stream<Item = Result<GarbleMessage, std::io::Error>> + Unpin,
        OT: OTReceiveEncoding,
    >(
        &self,
        id: &str,
        input_configs: &[ValueIdConfig],
        stream: &mut S,
        ot: &OT,
    ) -> Result<(), EvaluatorError> {
        let (ot_recv_values, direct_recv_values) = {
            let state = self.state();

            // Filter out any values that are already active.
            let mut input_configs: Vec<ValueIdConfig> = input_configs
                .iter()
                .cloned()
                .filter(|config| !state.encoding_registry.contains(config.id()))
                .collect();

            input_configs.sort_by_key(|config| config.id().clone());

            let mut ot_recv_values = Vec::new();
            let mut direct_recv_values = Vec::new();
            for config in input_configs.into_iter() {
                match config {
                    ValueIdConfig::Public { id, ty, .. } => {
                        direct_recv_values.push((id, ty));
                    }
                    ValueIdConfig::Private { id, ty, value } => {
                        if let Some(value) = value {
                            ot_recv_values.push((id, value));
                        } else {
                            direct_recv_values.push((id, ty));
                        }
                    }
                }
            }

            (ot_recv_values, direct_recv_values)
        };

        futures::try_join!(
            self.ot_receive_active_encodings(id, &ot_recv_values, ot),
            self.direct_receive_active_encodings(&direct_recv_values, stream)
        )?;

        Ok(())
    }

    /// Receives active encodings for the provided values via oblivious transfer.
    ///
    /// # Arguments
    /// - `id` - The id of this operation
    /// - `values` - The values to receive via oblivious transfer.
    /// - `ot` - The oblivious transfer receiver
    async fn ot_receive_active_encodings<OT: OTReceiveEncoding>(
        &self,
        id: &str,
        values: &[(ValueId, Value)],
        ot: &OT,
    ) -> Result<(), EvaluatorError> {
        if values.is_empty() {
            return Ok(());
        }

        let (ot_recv_ids, ot_recv_values): (Vec<ValueId>, Vec<Value>) =
            values.iter().cloned().unzip();

        let active_encodings = ot.receive(id, ot_recv_values).await?;

        // Make sure the generator sent the expected number of values.
        // This should be handled by the ot receiver, but we double-check anyways :)
        if active_encodings.len() != values.len() {
            return Err(EvaluatorError::IncorrectValueCount {
                expected: values.len(),
                actual: active_encodings.len(),
            });
        }

        let mut state = self.state();

        // Add the OT log
        state.ot_log.insert(id.to_string(), ot_recv_ids);

        for ((id, value), active_encoding) in values.iter().zip(active_encodings) {
            let expected_ty = value.value_type();
            // Make sure the generator sent the expected type.
            // This is also handled by the ot receiver, but we're paranoid.
            if active_encoding.value_type() != expected_ty {
                return Err(TypeError::UnexpectedType {
                    expected: expected_ty,
                    actual: active_encoding.value_type(),
                })?;
            }
            // Add the received values to the encoding registry.
            state
                .encoding_registry
                .set_encoding_by_id(id, active_encoding)?;
            state.received_values.insert(id.clone(), expected_ty);
        }

        Ok(())
    }

    /// Receives active encodings for the provided values directly from the generator.
    ///
    /// # Arguments
    /// - `values` - The values and types expected to be received
    /// - `stream` - The stream of messages from the generator
    async fn direct_receive_active_encodings<
        S: Stream<Item = Result<GarbleMessage, std::io::Error>> + Unpin,
    >(
        &self,
        values: &[(ValueId, ValueType)],
        stream: &mut S,
    ) -> Result<(), EvaluatorError> {
        if values.is_empty() {
            return Ok(());
        }

        let active_encodings = expect_msg_or_err!(stream, GarbleMessage::ActiveValues)?;

        // Make sure the generator sent the expected number of values.
        if active_encodings.len() != values.len() {
            return Err(EvaluatorError::IncorrectValueCount {
                expected: values.len(),
                actual: active_encodings.len(),
            });
        }

        let mut state = self.state();
        for ((id, expected_ty), active_encoding) in values.iter().zip(active_encodings) {
            // Make sure the generator sent the expected type.
            if &active_encoding.value_type() != expected_ty {
                return Err(TypeError::UnexpectedType {
                    expected: expected_ty.clone(),
                    actual: active_encoding.value_type(),
                })?;
            }
            // Add the received values to the encoding registry.
            state
                .encoding_registry
                .set_encoding_by_id(id, active_encoding)?;
            state
                .received_values
                .insert(id.clone(), expected_ty.clone());
        }

        Ok(())
    }

    /// Evaluate a garbled circuit, receiving the encrypted gates in batches from the provided stream.
    ///
    /// Returns the encoded outputs of the evaluated circuit.
    ///
    /// # Arguments
    ///
    /// * `circ` - The circuit to evaluate
    /// * `inputs` - The inputs to the circuit.
    /// * `outputs` - The outputs from the circuit.
    /// * `stream` - The stream of encrypted gates
    pub async fn evaluate<S: Stream<Item = Result<GarbleMessage, std::io::Error>> + Unpin>(
        &self,
        circ: Arc<Circuit>,
        inputs: &[ValueRef],
        outputs: &[ValueRef],
        stream: &mut S,
    ) -> Result<Vec<EncodedValue<encoding_state::Active>>, EvaluatorError> {
        let encoded_inputs = {
            let state = self.state();
            inputs
                .iter()
                .map(|value_ref| {
                    state
                        .encoding_registry
                        .get_encoding(value_ref)
                        .ok_or_else(|| EvaluatorError::MissingEncoding(value_ref.clone()))
                })
                .collect::<Result<Vec<_>, _>>()?
        };

        let mut ev = if self.config.log_circuits {
            EvaluatorCore::new_with_hasher(circ.clone(), &encoded_inputs)?
        } else {
            EvaluatorCore::new(circ.clone(), &encoded_inputs)?
        };

        while !ev.is_complete() {
            let encrypted_gates = expect_msg_or_err!(stream, GarbleMessage::EncryptedGates)?;

            for batch in encrypted_gates.chunks(self.config.batch_size) {
                let batch = batch.to_vec();
                // Move the evaluator to a new thread to process the batch then send it back
                ev = Backend::spawn(move || {
                    ev.evaluate(batch.iter());
                    ev
                })
                .await;
            }
        }

        let encoded_outputs = ev.outputs()?;

        // If configured, expect the output encoding commitments
        // from the generator and verify them.
        if self.config.encoding_commitments {
            let commitments = expect_msg_or_err!(stream, GarbleMessage::EncodingCommitments)?;

            // Make sure the generator sent the expected number of commitments.
            if commitments.len() != encoded_outputs.len() {
                return Err(EvaluatorError::IncorrectValueCount {
                    expected: encoded_outputs.len(),
                    actual: commitments.len(),
                });
            }

            for (output, commitment) in encoded_outputs.iter().zip(commitments) {
                commitment.verify(output)?;
            }
        }

        // Add the output encodings to the encoding registry.
        let mut state = self.state();
        for (output, encoding) in outputs.iter().zip(encoded_outputs.iter()) {
            state
                .encoding_registry
                .set_encoding(output, encoding.clone())?;
        }

        // If configured, log the circuit evaluation
        if self.config.log_circuits {
            let hash = ev.hash().unwrap();
            state.circuit_logs.push(EvaluatorLog::new(
                inputs.to_vec(),
                outputs.to_vec(),
                circ,
                hash,
            ));
        }

        Ok(encoded_outputs)
    }

    /// Receive decoding information for a set of values from the generator
    /// and decode them.
    ///
    /// # Arguments
    ///
    /// * `values` - The values to decode
    /// * `stream` - The stream from the generator
    pub async fn decode<S: Stream<Item = Result<GarbleMessage, std::io::Error>> + Unpin>(
        &self,
        values: &[ValueRef],
        stream: &mut S,
    ) -> Result<Vec<Value>, EvaluatorError> {
        let decodings = expect_msg_or_err!(stream, GarbleMessage::ValueDecodings)?;

        // Make sure the generator sent the expected number of decodings.
        if decodings.len() != values.len() {
            return Err(EvaluatorError::IncorrectValueCount {
                expected: values.len(),
                actual: decodings.len(),
            });
        }

        for (value, decoding) in values.iter().zip(decodings.iter()) {
            self.set_decoded(value)?;
            if self.config.log_decodings {
                self.add_decoding_log(value, decoding.clone());
            }
        }

        let active_encodings = values
            .iter()
            .map(|value| {
                self.get_encoding(value)
                    .ok_or_else(|| EvaluatorError::MissingEncoding(value.clone()))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let decoded_values = decodings
            .iter()
            .zip(active_encodings.iter())
            .map(|(decoding, encoding)| encoding.decode(decoding))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(decoded_values)
    }

    /// Verifies all the evaluator state using the generator's encoder seed and the OT verifier.
    ///
    /// # Arguments
    ///
    /// * `encoder_seed` - The seed used by the generator to generate encodings for input values.
    /// * `ot` - The OT verifier.
    pub async fn verify<T: OTVerifyEncoding>(
        &mut self,
        encoder_seed: [u8; 32],
        ot: &T,
    ) -> Result<(), EvaluatorError> {
        // This function requires an exclusive reference to self, and because this
        // object owns the Mutex, we are guaranteed that no other thread is accessing
        // the state during verification.

        let gen = Generator::new(
            GeneratorConfigBuilder::default().build().unwrap(),
            encoder_seed,
        );

        // Generate encodings for all received values
        let received_values: Vec<(ValueId, ValueType)> =
            self.state().received_values.drain().collect();
        gen.generate_encodings(&received_values)
            .map_err(VerificationError::from)?;

        // Verify all OTs in the log
        let mut ot_futs: FuturesUnordered<_> = self
            .state()
            .ot_log
            .iter()
            .map(|(ot_id, value_ids)| {
                let encoded_values = gen
                    .get_encodings_by_id(value_ids)
                    .expect("encodings should be present");
                let ot_id = ot_id.to_string();
                async move { ot.verify(&ot_id, encoded_values).await }
            })
            .collect();

        while let Some(result) = ot_futs.next().await {
            result?;
        }

        // Verify all garbled circuits in the log
        while !self.state().circuit_logs.is_empty() {
            // drain_filter is not stabilized.. such is life.
            // here we drain out log batches for which we have all the input encodings
            // computed at this point.
            let log_batch = self
                .state()
                .circuit_logs
                .filter_drain(|log| {
                    log.inputs
                        .iter()
                        .all(|input| gen.get_encoding(input).is_some())
                })
                .collect::<Vec<_>>();

            let mut batch_futs: FuturesUnordered<_> = log_batch
                .iter()
                .map(|log| async {
                    // Compute the garbled circuit digest
                    let (_, digest) = gen
                        .generate(
                            log.circ.clone(),
                            &log.inputs,
                            &log.outputs,
                            &mut futures::sink::drain().sink_map_err(|_| {
                                std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "")
                            }),
                            true,
                        )
                        .await
                        .map_err(VerificationError::from)?;

                    if digest.unwrap() != log.hash {
                        return Err(VerificationError::InvalidGarbledCircuit);
                    }

                    Ok(())
                })
                .collect();

            while let Some(result) = batch_futs.next().await {
                result?;
            }
        }

        // Verify all decodings in the log
        for (value, decoding) in self.state().decoding_logs.drain() {
            let encoding = gen.get_encoding(&value).expect("encoding should exist");

            if encoding.decoding() != decoding {
                return Err(VerificationError::InvalidDecoding)?;
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct EvaluatorLog {
    inputs: Vec<ValueRef>,
    outputs: Vec<ValueRef>,
    circ: Arc<Circuit>,
    hash: Hash,
}

impl EvaluatorLog {
    pub(crate) fn new(
        inputs: Vec<ValueRef>,
        outputs: Vec<ValueRef>,
        circ: Arc<Circuit>,
        digest: Hash,
    ) -> Self {
        Self {
            inputs,
            outputs,
            circ,
            hash: digest,
        }
    }
}
