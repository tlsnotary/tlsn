//! An implementation of the Dual-execution with Asymmetric Privacy (DEAP) protocol.

mod error;
pub mod mock;
mod vm;

use std::{
    collections::HashMap,
    ops::DerefMut,
    sync::{Arc, Mutex},
};

use futures::{Sink, SinkExt, Stream, StreamExt, TryFutureExt};
use mpc_circuits::{
    types::{StaticValueType, TypeError, Value, ValueType},
    Circuit,
};
use mpc_core::{
    commit::{Decommitment, HashCommit},
    hash::{Hash, SecureHash},
};
use mpc_garble_core::{msg::GarbleMessage, EqualityCheck};
use utils_aio::expect_msg_or_err;

use crate::{
    config::{Role, ValueConfig, Visibility},
    evaluator::{Evaluator, EvaluatorConfigBuilder},
    generator::{Generator, GeneratorConfigBuilder},
    ot::{OTReceiveEncoding, OTSendEncoding, OTVerifyEncoding},
    registry::ValueRegistry,
    Memory, MemoryError, ValueRef,
};

pub use error::DEAPError;
pub use vm::{DEAPThread, DEAPVm};

/// The DEAP protocol.
#[derive(Debug, Default)]
pub struct DEAP {
    role: Role,
    gen: Generator,
    ev: Evaluator,
    state: Mutex<State>,
    finalized: bool,
}

#[derive(Debug, Default)]
struct State {
    /// A registry of all values
    value_registry: ValueRegistry,
    /// An internal buffer for value configurations which get
    /// drained and set up prior to execution.
    input_buffer: HashMap<ValueRef, ValueConfig>,
    /// Equality check decommitments withheld by the leader
    /// prior to finalization
    eq_decommitments: HashMap<String, Decommitment<EqualityCheck>>,
    /// Equality check commitments from the leader
    eq_commitments: HashMap<String, (EqualityCheck, Hash)>,
    /// Proof decommitments withheld by the leader
    /// prior to finalization
    proof_decommitments: HashMap<String, Decommitment<Hash>>,
    /// Proof commitments from the leader
    proof_commitments: HashMap<String, (Hash, Hash)>,
}

impl DEAP {
    /// Creates a new DEAP protocol instance.
    pub fn new(role: Role, encoder_seed: [u8; 32]) -> Self {
        let mut gen_config_builder = GeneratorConfigBuilder::default();
        let mut ev_config_builder = EvaluatorConfigBuilder::default();

        match role {
            Role::Leader => {
                // Sends commitments to output encodings.
                gen_config_builder.encoding_commitments();
                // Logs evaluated circuits and decodings.
                ev_config_builder.log_circuits().log_decodings();
            }

            Role::Follower => {
                // Expects commitments to output encodings.
                ev_config_builder.encoding_commitments();
            }
        }

        let gen_config = gen_config_builder.build().expect("config should be valid");
        let ev_config = ev_config_builder.build().expect("config should be valid");

        let gen = Generator::new(gen_config, encoder_seed);
        let ev = Evaluator::new(ev_config);

        Self {
            role,
            gen,
            ev,
            ..Default::default()
        }
    }

    fn state(&self) -> impl DerefMut<Target = State> + '_ {
        self.state.lock().unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn execute<T, U, OTS, OTR>(
        &self,
        id: &str,
        circ: Arc<Circuit>,
        inputs: &[ValueRef],
        outputs: &[ValueRef],
        sink: &mut T,
        stream: &mut U,
        ot_send: &OTS,
        ot_recv: &OTR,
    ) -> Result<(), DEAPError>
    where
        T: Sink<GarbleMessage, Error = std::io::Error> + Unpin,
        U: Stream<Item = GarbleMessage> + Unpin,
        OTS: OTSendEncoding,
        OTR: OTReceiveEncoding,
    {
        let input_configs = {
            let mut state = self.state();

            inputs
                .iter()
                .filter_map(|input| state.input_buffer.remove(input))
                .collect::<Vec<_>>()
        };

        // Setup inputs concurrently.
        futures::try_join!(
            self.gen
                .setup_inputs(id, &input_configs, sink, ot_send)
                .map_err(DEAPError::from),
            self.ev
                .setup_inputs(id, &input_configs, stream, ot_recv)
                .map_err(DEAPError::from)
        )?;

        // Generate and evaluate concurrently.
        // Drop the encoded outputs, we don't need them here
        _ = futures::try_join!(
            self.gen
                .generate(circ.clone(), inputs, outputs, sink, false)
                .map_err(DEAPError::from),
            self.ev
                .evaluate(circ.clone(), inputs, outputs, stream)
                .map_err(DEAPError::from)
        )?;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn prove<T, U, OTR>(
        &self,
        id: &str,
        circ: Arc<Circuit>,
        inputs: &[ValueRef],
        outputs: &[ValueRef],
        sink: &mut T,
        stream: &mut U,
        ot_recv: &OTR,
    ) -> Result<(), DEAPError>
    where
        T: Sink<GarbleMessage, Error = std::io::Error> + Unpin,
        U: Stream<Item = GarbleMessage> + Unpin,
        OTR: OTReceiveEncoding,
    {
        if let Role::Follower = self.role {
            return Err(DEAPError::RoleError(
                "DEAP follower can not act as the prover".to_string(),
            ))?;
        }

        let input_configs = {
            let mut state = self.state();

            inputs
                .iter()
                .filter_map(|input| state.input_buffer.remove(input))
                .collect::<Vec<_>>()
        };

        self.ev
            .setup_inputs(id, &input_configs, stream, ot_recv)
            .map_err(DEAPError::from)
            .await?;

        let outputs = self
            .ev
            .evaluate(circ, inputs, outputs, stream)
            .map_err(DEAPError::from)
            .await?;

        let output_digest = outputs.hash();
        let (decommitment, commitment) = output_digest.hash_commit();

        // Store output proof decommitment until finalization
        self.state()
            .proof_decommitments
            .insert(id.to_string(), decommitment);

        sink.send(GarbleMessage::HashCommitment(commitment)).await?;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn verify<T, U, OTS>(
        &self,
        id: &str,
        circ: Arc<Circuit>,
        inputs: &[ValueRef],
        outputs: &[ValueRef],
        expected_outputs: &[Value],
        sink: &mut T,
        stream: &mut U,
        ot_send: &OTS,
    ) -> Result<(), DEAPError>
    where
        T: Sink<GarbleMessage, Error = std::io::Error> + Unpin,
        U: Stream<Item = GarbleMessage> + Unpin,
        OTS: OTSendEncoding,
    {
        if let Role::Leader = self.role {
            return Err(DEAPError::RoleError(
                "DEAP leader can not act as the verifier".to_string(),
            ))?;
        }

        let input_configs = {
            let mut state = self.state();

            inputs
                .iter()
                .filter_map(|input| state.input_buffer.remove(input))
                .collect::<Vec<_>>()
        };

        self.gen
            .setup_inputs(id, &input_configs, sink, ot_send)
            .map_err(DEAPError::from)
            .await?;

        let (encoded_outputs, _) = self
            .gen
            .generate(circ.clone(), inputs, outputs, sink, false)
            .map_err(DEAPError::from)
            .await?;

        let expected_outputs = expected_outputs
            .iter()
            .zip(encoded_outputs)
            .map(|(expected, encoded)| encoded.select(expected.clone()).unwrap())
            .collect::<Vec<_>>();

        let expected_digest = expected_outputs.hash();

        let commitment = expect_msg_or_err!(
            stream.next().await,
            GarbleMessage::HashCommitment,
            DEAPError::UnexpectedMessage
        )?;

        self.state()
            .proof_commitments
            .insert(id.to_string(), (expected_digest, commitment));

        Ok(())
    }

    pub(crate) async fn decode<T, U>(
        &self,
        id: &str,
        values: &[ValueRef],
        sink: &mut T,
        stream: &mut U,
    ) -> Result<Vec<Value>, DEAPError>
    where
        T: Sink<GarbleMessage, Error = std::io::Error> + Unpin,
        U: Stream<Item = GarbleMessage> + Unpin,
    {
        let full = values
            .iter()
            .map(|value| {
                self.gen
                    .get_encoding(value)
                    .ok_or(DEAPError::MissingEncoding(value.clone()))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let active = values
            .iter()
            .map(|value| {
                self.ev
                    .get_encoding(value)
                    .ok_or(DEAPError::MissingEncoding(value.clone()))
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Decode concurrently.
        let (_, purported_values) = futures::try_join!(
            self.gen.decode(values, sink).map_err(DEAPError::from),
            self.ev.decode(values, stream).map_err(DEAPError::from),
        )?;

        let eq_check = EqualityCheck::new(
            &full,
            &active,
            &purported_values,
            match self.role {
                Role::Leader => false,
                Role::Follower => true,
            },
        );

        let output = match self.role {
            Role::Leader => {
                let (decommitment, commit) = eq_check.hash_commit();

                // Store equality check decommitment until finalization
                self.state()
                    .eq_decommitments
                    .insert(id.to_string(), decommitment);

                // Send commitment to equality check to follower
                sink.send(GarbleMessage::HashCommitment(commit)).await?;

                // Receive the active encoded outputs from the follower
                let active = expect_msg_or_err!(
                    stream.next().await,
                    GarbleMessage::ActiveValues,
                    DEAPError::UnexpectedMessage
                )?;

                // Authentic values
                active
                    .into_iter()
                    .zip(full)
                    .map(|(active, full)| full.decode(&active))
                    .collect::<Result<Vec<_>, _>>()?
            }
            Role::Follower => {
                // Receive equality check commitment from leader
                let commit = expect_msg_or_err!(
                    stream.next().await,
                    GarbleMessage::HashCommitment,
                    DEAPError::UnexpectedMessage
                )?;

                // Store equality check commitment until finalization
                self.state()
                    .eq_commitments
                    .insert(id.to_string(), (eq_check, commit));

                // Send active encoded values to leader
                sink.send(GarbleMessage::ActiveValues(active)).await?;

                // Assume purported values are correct until finalization
                purported_values
            }
        };

        Ok(output)
    }

    /// Finalize the DEAP instance.
    ///
    /// This function will reveal all private inputs of the follower
    ///
    /// # Arguments
    ///
    /// - `channel` - The channel to communicate with the other party
    /// - `ot` - The OT verifier to use
    pub async fn finalize<
        T: Sink<GarbleMessage, Error = std::io::Error> + Unpin,
        U: Stream<Item = GarbleMessage> + Unpin,
        OT: OTVerifyEncoding,
    >(
        &mut self,
        sink: &mut T,
        stream: &mut U,
        ot: &OT,
    ) -> Result<(), DEAPError> {
        if self.finalized {
            return Err(DEAPError::AlreadyFinalized);
        } else {
            self.finalized = true;
        }

        // Drain the state
        let (
            mut eq_decommitments,
            mut eq_commitments,
            mut proof_decommitments,
            mut proof_commitments,
        ) = {
            let mut state = self.state();
            (
                state.eq_decommitments.drain().collect::<Vec<_>>(),
                state.eq_commitments.drain().collect::<Vec<_>>(),
                state.proof_decommitments.drain().collect::<Vec<_>>(),
                state.proof_commitments.drain().collect::<Vec<_>>(),
            )
        };

        // Sort the decommitments and commitments by id
        eq_decommitments.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
        eq_commitments.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
        proof_decommitments.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
        proof_commitments.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());

        match self.role {
            Role::Leader => {
                // Receive the encoder seed from the follower.
                let encoder_seed = expect_msg_or_err!(
                    stream.next().await,
                    GarbleMessage::EncoderSeed,
                    DEAPError::UnexpectedMessage
                )?;

                let encoder_seed: [u8; 32] = encoder_seed.try_into().unwrap();

                // Verify all oblivious transfers, garbled circuits and decodings
                // sent by the follower.
                self.ev.verify(encoder_seed, ot).await?;

                // Reveal the equality check decommitments to the follower.
                sink.send(GarbleMessage::EqualityCheckDecommitments(
                    eq_decommitments
                        .into_iter()
                        .map(|(_, decommitment)| decommitment)
                        .collect(),
                ))
                .await?;

                // Reveal the proof decommitments to the follower.
                sink.send(GarbleMessage::ProofDecommitments(
                    proof_decommitments
                        .into_iter()
                        .map(|(_, decommitment)| decommitment)
                        .collect(),
                ))
                .await?;
            }
            Role::Follower => {
                let encoder_seed = self.gen.seed();

                sink.send(GarbleMessage::EncoderSeed(encoder_seed.to_vec()))
                    .await?;

                // Receive the equality check decommitments from the leader.
                let eq_decommitments = expect_msg_or_err!(
                    stream.next().await,
                    GarbleMessage::EqualityCheckDecommitments,
                    DEAPError::UnexpectedMessage
                )?;

                // Receive the proof decommitments from the leader.
                let proof_decommitments = expect_msg_or_err!(
                    stream.next().await,
                    GarbleMessage::ProofDecommitments,
                    DEAPError::UnexpectedMessage
                )?;

                // Verify all equality checks.
                for (decommitment, (_, (expected_check, commitment))) in
                    eq_decommitments.iter().zip(eq_commitments.iter())
                {
                    decommitment
                        .verify(commitment)
                        .map_err(|_| DEAPError::InvalidEqualityCheck)?;
                    if decommitment.data() != expected_check {
                        return Err(DEAPError::InvalidEqualityCheck);
                    }
                }

                // Verify all proofs.
                for (decommitment, (_, (expected_digest, commitment))) in
                    proof_decommitments.iter().zip(proof_commitments.iter())
                {
                    decommitment
                        .verify(commitment)
                        .map_err(|_| DEAPError::InvalidProof)?;
                    if decommitment.data() != expected_digest {
                        return Err(DEAPError::InvalidProof);
                    }
                }
            }
        }

        Ok(())
    }
}

impl Memory for DEAP {
    fn new_public_input<T: StaticValueType>(
        &self,
        id: &str,
        value: T,
    ) -> Result<ValueRef, crate::MemoryError> {
        let mut state = self.state();

        let ty = T::value_type();
        let value_ref = state.value_registry.add_value(id, ty)?;
        let config =
            ValueConfig::new_public::<T>(value_ref.clone(), value).expect("config is valid");
        state.input_buffer.insert(value_ref.clone(), config);

        Ok(value_ref)
    }

    fn new_public_array_input<T: StaticValueType>(
        &self,
        id: &str,
        value: Vec<T>,
    ) -> Result<ValueRef, crate::MemoryError>
    where
        Vec<T>: Into<Value>,
    {
        let mut state = self.state();

        let value: Value = value.into();
        let ty = value.value_type();
        let value_ref = state.value_registry.add_value(id, ty)?;
        let config =
            ValueConfig::new_public::<T>(value_ref.clone(), value).expect("config is valid");
        state.input_buffer.insert(value_ref.clone(), config);

        Ok(value_ref)
    }

    fn new_public_input_by_type(&self, id: &str, value: Value) -> Result<ValueRef, MemoryError> {
        let mut state = self.state();

        let ty = value.value_type();
        let value_ref = state.value_registry.add_value(id, ty.clone())?;
        let config = ValueConfig::new(value_ref.clone(), ty, Some(value), Visibility::Public)
            .expect("config is valid");
        state.input_buffer.insert(value_ref.clone(), config);

        Ok(value_ref)
    }

    fn new_private_input<T: StaticValueType>(
        &self,
        id: &str,
        value: Option<T>,
    ) -> Result<ValueRef, crate::MemoryError> {
        let mut state = self.state();

        let ty = T::value_type();
        let value_ref = state.value_registry.add_value(id, ty)?;
        let config =
            ValueConfig::new_private::<T>(value_ref.clone(), value).expect("config is valid");
        state.input_buffer.insert(value_ref.clone(), config);

        Ok(value_ref)
    }

    fn new_private_array_input<T: StaticValueType>(
        &self,
        id: &str,
        value: Option<Vec<T>>,
        len: usize,
    ) -> Result<ValueRef, crate::MemoryError>
    where
        Vec<T>: Into<Value>,
    {
        let mut state = self.state();

        let ty = ValueType::new_array::<T>(len);
        let value_ref = state.value_registry.add_value(id, ty)?;
        let config = ValueConfig::new_private_array::<T>(value_ref.clone(), value, len)
            .expect("config is valid");
        state.input_buffer.insert(value_ref.clone(), config);

        Ok(value_ref)
    }

    fn new_private_input_by_type(
        &self,
        id: &str,
        ty: &ValueType,
        value: Option<Value>,
    ) -> Result<ValueRef, MemoryError> {
        if let Some(value) = &value {
            if &value.value_type() != ty {
                return Err(TypeError::UnexpectedType {
                    expected: ty.clone(),
                    actual: value.value_type(),
                })?;
            }
        }

        let mut state = self.state();

        let value_ref = state.value_registry.add_value(id, ty.clone())?;
        let config = ValueConfig::new(value_ref.clone(), ty.clone(), value, Visibility::Private)
            .expect("config is valid");
        state.input_buffer.insert(value_ref.clone(), config);

        Ok(value_ref)
    }

    fn new_output<T: StaticValueType>(&self, id: &str) -> Result<ValueRef, crate::MemoryError> {
        let mut state = self.state();

        let ty = T::value_type();
        let value_ref = state.value_registry.add_value(id, ty)?;

        Ok(value_ref)
    }

    fn new_array_output<T: StaticValueType>(
        &self,
        id: &str,
        len: usize,
    ) -> Result<ValueRef, crate::MemoryError>
    where
        Vec<T>: Into<Value>,
    {
        let mut state = self.state();

        let ty = ValueType::new_array::<T>(len);
        let value_ref = state.value_registry.add_value(id, ty)?;

        Ok(value_ref)
    }

    fn new_output_by_type(&self, id: &str, ty: &ValueType) -> Result<ValueRef, MemoryError> {
        let mut state = self.state();

        let value_ref = state.value_registry.add_value(id, ty.clone())?;

        Ok(value_ref)
    }

    fn get_value(&self, id: &str) -> Option<ValueRef> {
        self.state().value_registry.get_value(id)
    }

    fn get_value_type(&self, id: &str) -> Option<ValueType> {
        self.state().value_registry.get_value_type(id)
    }
}

#[cfg(test)]
mod tests {
    use mpc_circuits::circuits::AES128;
    use mpc_ot::mock::mock_ot_pair;
    use utils_aio::duplex::DuplexChannel;

    use super::*;

    #[tokio::test]
    async fn test_deap() {
        let (leader_channel, follower_channel) = DuplexChannel::<GarbleMessage>::new();
        let (leader_ot_send, follower_ot_recv) = mock_ot_pair();
        let (follower_ot_send, leader_ot_recv) = mock_ot_pair();

        let mut leader = DEAP::new(Role::Leader, [42u8; 32]);
        let mut follower = DEAP::new(Role::Follower, [69u8; 32]);

        let key = [42u8; 16];
        let msg = [69u8; 16];

        let leader_fut = {
            let (mut sink, mut stream) = leader_channel.split();

            let key_ref = leader.new_private_input("key", Some(key)).unwrap();
            let msg_ref = leader.new_private_input::<[u8; 16]>("msg", None).unwrap();
            let ciphertext_ref = leader.new_output::<[u8; 16]>("ciphertext").unwrap();

            async move {
                leader
                    .execute(
                        "test",
                        AES128.clone(),
                        &[key_ref, msg_ref],
                        &[ciphertext_ref.clone()],
                        &mut sink,
                        &mut stream,
                        &leader_ot_send,
                        &leader_ot_recv,
                    )
                    .await
                    .unwrap();

                let outputs = leader
                    .decode("test", &[ciphertext_ref], &mut sink, &mut stream)
                    .await
                    .unwrap();

                leader
                    .finalize(&mut sink, &mut stream, &leader_ot_recv)
                    .await
                    .unwrap();

                outputs
            }
        };

        let follower_fut = {
            let (mut sink, mut stream) = follower_channel.split();

            let key_ref = follower.new_private_input::<[u8; 16]>("key", None).unwrap();
            let msg_ref = follower.new_private_input("msg", Some(msg)).unwrap();
            let ciphertext_ref = follower.new_output::<[u8; 16]>("ciphertext").unwrap();

            async move {
                follower
                    .execute(
                        "test",
                        AES128.clone(),
                        &[key_ref, msg_ref],
                        &[ciphertext_ref.clone()],
                        &mut sink,
                        &mut stream,
                        &follower_ot_send,
                        &follower_ot_recv,
                    )
                    .await
                    .unwrap();

                let outputs = follower
                    .decode("test", &[ciphertext_ref], &mut sink, &mut stream)
                    .await
                    .unwrap();

                follower
                    .finalize(&mut sink, &mut stream, &follower_ot_recv)
                    .await
                    .unwrap();

                outputs
            }
        };

        let (leader_output, follower_output) = tokio::join!(leader_fut, follower_fut);

        assert_eq!(leader_output, follower_output);
    }

    #[tokio::test]
    async fn test_deap_zk_pass() {
        run_zk(
            [42u8; 16],
            [69u8; 16],
            [
                235u8, 22, 253, 138, 102, 20, 139, 100, 252, 153, 244, 111, 84, 116, 199, 75,
            ],
        )
        .await;
    }

    #[tokio::test]
    #[should_panic]
    async fn test_deap_zk_fail() {
        run_zk(
            [42u8; 16],
            [69u8; 16],
            // wrong ciphertext
            [
                235u8, 22, 253, 138, 102, 20, 139, 100, 252, 153, 244, 111, 84, 116, 199, 76,
            ],
        )
        .await;
    }

    async fn run_zk(key: [u8; 16], msg: [u8; 16], expected_ciphertext: [u8; 16]) {
        let (leader_channel, follower_channel) = DuplexChannel::<GarbleMessage>::new();
        let (_, follower_ot_recv) = mock_ot_pair();
        let (follower_ot_send, leader_ot_recv) = mock_ot_pair();

        let mut leader = DEAP::new(Role::Leader, [42u8; 32]);
        let mut follower = DEAP::new(Role::Follower, [69u8; 32]);

        let leader_fut = {
            let (mut sink, mut stream) = leader_channel.split();
            let key_ref = leader
                .new_private_input::<[u8; 16]>("key", Some(key))
                .unwrap();
            let msg_ref = leader.new_private_input::<[u8; 16]>("msg", None).unwrap();
            let ciphertext_ref = leader.new_output::<[u8; 16]>("ciphertext").unwrap();

            async move {
                leader
                    .prove(
                        "test",
                        AES128.clone(),
                        &[key_ref, msg_ref],
                        &[ciphertext_ref],
                        &mut sink,
                        &mut stream,
                        &leader_ot_recv,
                    )
                    .await
                    .unwrap();

                leader
                    .finalize(&mut sink, &mut stream, &leader_ot_recv)
                    .await
                    .unwrap();
            }
        };

        let follower_fut = {
            let (mut sink, mut stream) = follower_channel.split();
            let key_ref = follower.new_private_input::<[u8; 16]>("key", None).unwrap();
            let msg_ref = follower
                .new_private_input::<[u8; 16]>("msg", Some(msg))
                .unwrap();
            let ciphertext_ref = follower.new_output::<[u8; 16]>("ciphertext").unwrap();

            async move {
                follower
                    .verify(
                        "test",
                        AES128.clone(),
                        &[key_ref, msg_ref],
                        &[ciphertext_ref],
                        &[expected_ciphertext.into()],
                        &mut sink,
                        &mut stream,
                        &follower_ot_send,
                    )
                    .await
                    .unwrap();

                follower
                    .finalize(&mut sink, &mut stream, &follower_ot_recv)
                    .await
                    .unwrap();
            }
        };

        futures::join!(leader_fut, follower_fut);
    }
}
