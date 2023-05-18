//! An implementation of the Dual-execution with Asymmetric Privacy (DEAP) protocol.
//!
//! For more information, see the [DEAP specification](https://docs.tlsnotary.org/protocol/2pc/deap.html).

mod error;
mod memory;
pub mod mock;
mod vm;

use std::{
    collections::HashMap,
    ops::DerefMut,
    sync::{Arc, Mutex},
};

use futures::{Sink, SinkExt, Stream, StreamExt, TryFutureExt};
use mpc_circuits::{types::Value, Circuit};
use mpc_core::{
    commit::{Decommitment, HashCommit},
    hash::{Hash, SecureHash},
    value::{ValueId, ValueRef},
};
use mpc_garble_core::{msg::GarbleMessage, EqualityCheck};
use rand::thread_rng;
use utils_aio::expect_msg_or_err;

use crate::{
    config::{Role, ValueConfig, ValueIdConfig, Visibility},
    evaluator::{Evaluator, EvaluatorConfigBuilder},
    generator::{Generator, GeneratorConfigBuilder},
    internal_circuits::{build_otp_circuit, build_otp_shared_circuit},
    ot::{OTReceiveEncoding, OTSendEncoding, OTVerifyEncoding},
    registry::ValueRegistry,
};

pub use error::{DEAPError, PeerEncodingsError};
pub use vm::{DEAPThread, DEAPVm};

use self::error::FinalizationError;

/// The DEAP protocol.
#[derive(Debug)]
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
    input_buffer: HashMap<ValueId, ValueIdConfig>,

    /// Equality check decommitments withheld by the leader
    /// prior to finalization
    ///
    /// Operation ID => Equality check decommitment
    eq_decommitments: HashMap<String, Decommitment<EqualityCheck>>,
    /// Equality check commitments from the leader
    ///
    /// Operation ID => (Expected eq. check value, hash commitment from leader)
    eq_commitments: HashMap<String, (EqualityCheck, Hash)>,
    /// Proof decommitments withheld by the leader
    /// prior to finalization
    ///
    /// Operation ID => GC output hash decommitment
    proof_decommitments: HashMap<String, Decommitment<Hash>>,
    /// Proof commitments from the leader
    ///
    /// Operation ID => (Expected GC output hash, hash commitment from leader)
    proof_commitments: HashMap<String, (Hash, Hash)>,
}

struct FinalizedState {
    /// Equality check decommitments withheld by the leader
    /// prior to finalization
    eq_decommitments: Vec<(String, Decommitment<EqualityCheck>)>,
    /// Equality check commitments from the leader
    eq_commitments: Vec<(String, (EqualityCheck, Hash))>,
    /// Proof decommitments withheld by the leader
    /// prior to finalization
    proof_decommitments: Vec<(String, Decommitment<Hash>)>,
    /// Proof commitments from the leader
    proof_commitments: Vec<(String, (Hash, Hash))>,
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
            state: Mutex::new(State::default()),
            finalized: false,
        }
    }

    fn state(&self) -> impl DerefMut<Target = State> + '_ {
        self.state.lock().unwrap()
    }

    /// Executes a circuit.
    ///
    /// # Arguments
    ///
    /// * `id` - The ID of the circuit.
    /// * `circ` - The circuit to execute.
    /// * `inputs` - The inputs to the circuit.
    /// * `outputs` - The outputs to the circuit.
    /// * `sink` - The sink to send messages to.
    /// * `stream` - The stream to receive messages from.
    /// * `ot_send` - The OT sender.
    /// * `ot_recv` - The OT receiver.
    #[allow(clippy::too_many_arguments)]
    pub async fn execute<T, U, OTS, OTR>(
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
        let input_configs = self.state().remove_input_configs(inputs);

        let id_0 = format!("{}/0", id);
        let id_1 = format!("{}/1", id);

        let (gen_id, ev_id) = match self.role {
            Role::Leader => (id_0, id_1),
            Role::Follower => (id_1, id_0),
        };

        // Setup inputs concurrently.
        futures::try_join!(
            self.gen
                .setup_inputs(&gen_id, &input_configs, sink, ot_send)
                .map_err(DEAPError::from),
            self.ev
                .setup_inputs(&ev_id, &input_configs, stream, ot_recv)
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

    /// Proves the output of a circuit to the other party.
    ///
    /// # Notes
    ///
    /// This function can only be called by the leader.
    ///
    /// This function does _not_ prove the output right away,
    /// instead the proof is committed to and decommitted later during
    /// the call to [`finalize`](Self::finalize).
    ///
    /// # Arguments
    ///
    /// * `id` - The ID of the circuit.
    /// * `circ` - The circuit to execute.
    /// * `inputs` - The inputs to the circuit.
    /// * `outputs` - The outputs to the circuit.
    /// * `sink` - The sink to send messages to.
    /// * `stream` - The stream to receive messages from.
    /// * `ot_recv` - The OT receiver.
    #[allow(clippy::too_many_arguments)]
    pub async fn defer_prove<T, U, OTR>(
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
        if matches!(self.role, Role::Follower) {
            return Err(DEAPError::RoleError(
                "DEAP follower can not act as the prover".to_string(),
            ))?;
        }

        let input_configs = self.state().remove_input_configs(inputs);

        // The prover only acts as the evaluator for ZKPs instead of
        // dual-execution.
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

    /// Verifies the output of a circuit.
    ///
    /// # Notes
    ///
    /// This function can only be called by the follower.
    ///
    /// This function does _not_ verify the output right away,
    /// instead the leader commits to the proof and later it is checked
    /// during the call to [`finalize`](Self::finalize).
    ///
    /// # Arguments
    ///
    /// * `id` - The ID of the circuit.
    /// * `circ` - The circuit to execute.
    /// * `inputs` - The inputs to the circuit.
    /// * `outputs` - The outputs to the circuit.
    /// * `expected_outputs` - The expected outputs of the circuit.
    /// * `sink` - The sink to send messages to.
    /// * `stream` - The stream to receive messages from.
    /// * `ot_send` - The OT sender.
    #[allow(clippy::too_many_arguments)]
    pub async fn defer_verify<T, U, OTS>(
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
        if matches!(self.role, Role::Leader) {
            return Err(DEAPError::RoleError(
                "DEAP leader can not act as the verifier".to_string(),
            ))?;
        }

        let input_configs = self.state().remove_input_configs(inputs);

        // The verifier only acts as the generator for ZKPs instead of
        // dual-execution.
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

        // Store commitment to proof until finalization
        self.state()
            .proof_commitments
            .insert(id.to_string(), (expected_digest, commitment));

        Ok(())
    }

    /// Decodes the provided values, revealing the plaintext value to both parties.
    ///
    /// # Notes
    ///
    /// The dual-execution equality check is deferred until [`finalize`](Self::finalize).
    ///
    /// For the leader, the authenticity of the decoded values is guaranteed. Conversely,
    /// the follower can not be sure that the values are authentic until the equality check
    /// is performed later during [`finalize`](Self::finalize).
    ///
    /// # Arguments
    ///
    /// * `id` - The ID of the operation
    /// * `values` - The values to decode
    /// * `sink` - The sink to send messages to.
    /// * `stream` - The stream to receive messages from.
    pub async fn decode<T, U>(
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

                // Authenticate and decode values
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

    pub(crate) async fn decode_private<T, U, OTS, OTR>(
        &self,
        id: &str,
        values: &[ValueRef],
        sink: &mut T,
        stream: &mut U,
        ot_send: &OTS,
        ot_recv: &OTR,
    ) -> Result<Vec<Value>, DEAPError>
    where
        T: Sink<GarbleMessage, Error = std::io::Error> + Unpin,
        U: Stream<Item = GarbleMessage> + Unpin,
        OTS: OTSendEncoding,
        OTR: OTReceiveEncoding,
    {
        let (otp_refs, masked_refs): (Vec<_>, Vec<_>) = values
            .iter()
            .map(|value| (value.append_id("otp"), value.append_id("masked")))
            .unzip();

        let (otp_tys, otp_values) = {
            let mut state = self.state();

            let otp_tys = values
                .iter()
                .map(|value| {
                    state
                        .value_registry
                        .get_value_type_with_ref(value)
                        .ok_or_else(|| DEAPError::ValueDoesNotExist(value.clone()))
                })
                .collect::<Result<Vec<_>, _>>()?;

            let otp_values = otp_tys
                .iter()
                .map(|ty| Value::random(&mut thread_rng(), ty))
                .collect::<Vec<_>>();

            for ((otp_ref, otp_ty), otp_value) in
                otp_refs.iter().zip(otp_tys.iter()).zip(otp_values.iter())
            {
                state.add_input_config(
                    otp_ref,
                    ValueConfig::new(
                        otp_ref.clone(),
                        otp_ty.clone(),
                        Some(otp_value.clone()),
                        Visibility::Private,
                    )
                    .expect("config is valid"),
                );
            }

            (otp_tys, otp_values)
        };

        // Apply OTPs to values
        let circ = build_otp_circuit(&otp_tys);

        let inputs = values
            .iter()
            .zip(otp_refs.iter())
            .flat_map(|(value, otp)| [value, otp])
            .cloned()
            .collect::<Vec<_>>();

        self.execute(
            id,
            circ,
            &inputs,
            &masked_refs,
            sink,
            stream,
            ot_send,
            ot_recv,
        )
        .await?;

        // Decode masked values
        let masked_values = self.decode(id, &masked_refs, sink, stream).await?;

        // Remove OTPs, returning plaintext values
        Ok(masked_values
            .into_iter()
            .zip(otp_values)
            .map(|(masked, otp)| (masked ^ otp).expect("values are same type"))
            .collect())
    }

    pub(crate) async fn decode_blind<T, U, OTS, OTR>(
        &self,
        id: &str,
        values: &[ValueRef],
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
        let (otp_refs, masked_refs): (Vec<_>, Vec<_>) = values
            .iter()
            .map(|value| (value.append_id("otp"), value.append_id("masked")))
            .unzip();

        let otp_tys = {
            let mut state = self.state();

            let otp_tys = values
                .iter()
                .map(|value| {
                    state
                        .value_registry
                        .get_value_type_with_ref(value)
                        .ok_or_else(|| DEAPError::ValueDoesNotExist(value.clone()))
                })
                .collect::<Result<Vec<_>, _>>()?;

            for (otp_ref, otp_ty) in otp_refs.iter().zip(otp_tys.iter()) {
                state.add_input_config(
                    otp_ref,
                    ValueConfig::new(otp_ref.clone(), otp_ty.clone(), None, Visibility::Private)
                        .expect("config is valid"),
                );
            }

            otp_tys
        };

        // Apply OTPs to values
        let circ = build_otp_circuit(&otp_tys);

        let inputs = values
            .iter()
            .zip(otp_refs.iter())
            .flat_map(|(value, otp)| [value, otp])
            .cloned()
            .collect::<Vec<_>>();

        self.execute(
            id,
            circ,
            &inputs,
            &masked_refs,
            sink,
            stream,
            ot_send,
            ot_recv,
        )
        .await?;

        // Discard masked values
        _ = self.decode(id, &masked_refs, sink, stream).await?;

        Ok(())
    }

    pub(crate) async fn decode_shared<T, U, OTS, OTR>(
        &self,
        id: &str,
        values: &[ValueRef],
        sink: &mut T,
        stream: &mut U,
        ot_send: &OTS,
        ot_recv: &OTR,
    ) -> Result<Vec<Value>, DEAPError>
    where
        T: Sink<GarbleMessage, Error = std::io::Error> + Unpin,
        U: Stream<Item = GarbleMessage> + Unpin,
        OTS: OTSendEncoding,
        OTR: OTReceiveEncoding,
    {
        let (otp_0_refs, (otp_1_refs, masked_refs)): (Vec<_>, (Vec<_>, Vec<_>)) = values
            .iter()
            .map(|value| {
                (
                    value.append_id("otp_0"),
                    (value.append_id("otp_1"), value.append_id("masked")),
                )
            })
            .unzip();

        let (otp_tys, otp_values) = {
            let mut state = self.state();

            let otp_tys = values
                .iter()
                .map(|value| {
                    state
                        .value_registry
                        .get_value_type_with_ref(value)
                        .ok_or_else(|| DEAPError::ValueDoesNotExist(value.clone()))
                })
                .collect::<Result<Vec<_>, _>>()?;

            let otp_values = otp_tys
                .iter()
                .map(|ty| Value::random(&mut thread_rng(), ty))
                .collect::<Vec<_>>();

            for (((otp_0_ref, opt_1_ref), otp_ty), otp_value) in otp_0_refs
                .iter()
                .zip(&otp_1_refs)
                .zip(&otp_tys)
                .zip(&otp_values)
            {
                let (otp_0_config, otp_1_config) = match self.role {
                    Role::Leader => (
                        ValueConfig::new(
                            otp_0_ref.clone(),
                            otp_ty.clone(),
                            Some(otp_value.clone()),
                            Visibility::Private,
                        )
                        .expect("config is valid"),
                        ValueConfig::new(
                            opt_1_ref.clone(),
                            otp_ty.clone(),
                            None,
                            Visibility::Private,
                        )
                        .expect("config is valid"),
                    ),
                    Role::Follower => (
                        ValueConfig::new(
                            otp_0_ref.clone(),
                            otp_ty.clone(),
                            None,
                            Visibility::Private,
                        )
                        .expect("config is valid"),
                        ValueConfig::new(
                            opt_1_ref.clone(),
                            otp_ty.clone(),
                            Some(otp_value.clone()),
                            Visibility::Private,
                        )
                        .expect("config is valid"),
                    ),
                };
                state.add_input_config(otp_0_ref, otp_0_config);
                state.add_input_config(opt_1_ref, otp_1_config);
            }

            (otp_tys, otp_values)
        };

        // Apply OTPs to values
        let circ = build_otp_shared_circuit(&otp_tys);

        let inputs = values
            .iter()
            .zip(&otp_0_refs)
            .zip(&otp_1_refs)
            .flat_map(|((value, otp_0), otp_1)| [value, otp_0, otp_1])
            .cloned()
            .collect::<Vec<_>>();

        self.execute(
            id,
            circ,
            &inputs,
            &masked_refs,
            sink,
            stream,
            ot_send,
            ot_recv,
        )
        .await?;

        // Decode masked values
        let masked_values = self.decode(id, &masked_refs, sink, stream).await?;

        match self.role {
            Role::Leader => {
                // Leader removes his OTP
                Ok(masked_values
                    .into_iter()
                    .zip(otp_values)
                    .map(|(masked, otp)| (masked ^ otp).expect("values are the same type"))
                    .collect::<Vec<_>>())
            }
            Role::Follower => {
                // Follower uses his OTP as his share
                Ok(otp_values)
            }
        }
    }

    /// Finalize the DEAP instance.
    ///
    /// # Notes
    ///
    /// **This function will reveal all private inputs of the follower.**
    ///
    /// The follower reveals all his secrets to the leader, who can then verify
    /// that all oblivious transfers, circuit garbling, and value decoding was
    /// performed correctly.
    ///
    /// After the leader has verified everything, they decommit to all equality checks
    /// and ZK proofs from the session. The follower then verifies the decommitments
    /// and that all the equality checks and proofs were performed as expected.
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
            return Err(FinalizationError::AlreadyFinalized)?;
        } else {
            self.finalized = true;
        }

        let FinalizedState {
            eq_commitments,
            eq_decommitments,
            proof_commitments,
            proof_decommitments,
        } = self.state().finalize_state();

        match self.role {
            Role::Leader => {
                // Receive the encoder seed from the follower.
                let encoder_seed = expect_msg_or_err!(
                    stream.next().await,
                    GarbleMessage::EncoderSeed,
                    DEAPError::UnexpectedMessage
                )?;

                let encoder_seed: [u8; 32] = encoder_seed
                    .try_into()
                    .map_err(|_| FinalizationError::InvalidEncoderSeed)?;

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
                        .map_err(FinalizationError::from)?;

                    if decommitment.data() != expected_check {
                        return Err(FinalizationError::InvalidEqualityCheck)?;
                    }
                }

                // Verify all proofs.
                for (decommitment, (_, (expected_digest, commitment))) in
                    proof_decommitments.iter().zip(proof_commitments.iter())
                {
                    decommitment
                        .verify(commitment)
                        .map_err(FinalizationError::from)?;

                    if decommitment.data() != expected_digest {
                        return Err(FinalizationError::InvalidProof)?;
                    }
                }
            }
        }

        Ok(())
    }

    // Returns a reference to the evaluator
    pub(crate) fn ev(&self) -> &Evaluator {
        &self.ev
    }
}

impl State {
    /// Adds input configs to the buffer.
    fn add_input_config(&mut self, value: &ValueRef, config: ValueConfig) {
        value
            .iter()
            .zip(config.flatten())
            .for_each(|(id, config)| _ = self.input_buffer.insert(id.clone(), config));
    }

    /// Returns input configs from the buffer.
    fn remove_input_configs(&mut self, values: &[ValueRef]) -> Vec<ValueIdConfig> {
        values
            .iter()
            .flat_map(|value| value.iter())
            .filter_map(|id| self.input_buffer.remove(id))
            .collect::<Vec<_>>()
    }

    /// Drain the states to be finalized.
    fn finalize_state(&mut self) -> FinalizedState {
        let (
            mut eq_decommitments,
            mut eq_commitments,
            mut proof_decommitments,
            mut proof_commitments,
        ) = {
            (
                self.eq_decommitments.drain().collect::<Vec<_>>(),
                self.eq_commitments.drain().collect::<Vec<_>>(),
                self.proof_decommitments.drain().collect::<Vec<_>>(),
                self.proof_commitments.drain().collect::<Vec<_>>(),
            )
        };

        // Sort the decommitments and commitments by id
        eq_decommitments.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
        eq_commitments.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
        proof_decommitments.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
        proof_commitments.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());

        FinalizedState {
            eq_decommitments,
            eq_commitments,
            proof_decommitments,
            proof_commitments,
        }
    }
}

#[cfg(test)]
mod tests {
    use mpc_circuits::{circuits::AES128, ops::WrappingAdd, CircuitBuilder};
    use mpc_ot::mock::mock_ot_pair;
    use utils_aio::duplex::DuplexChannel;

    use crate::Memory;

    use super::*;

    fn adder_circ() -> Arc<Circuit> {
        let builder = CircuitBuilder::new();

        let a = builder.add_input::<u8>();
        let b = builder.add_input::<u8>();

        let c = a.wrapping_add(b);

        builder.add_output(c);

        Arc::new(builder.build().unwrap())
    }

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
    async fn test_deap_decode_private() {
        let (leader_channel, follower_channel) = DuplexChannel::<GarbleMessage>::new();
        let (leader_ot_send, follower_ot_recv) = mock_ot_pair();
        let (follower_ot_send, leader_ot_recv) = mock_ot_pair();

        let mut leader = DEAP::new(Role::Leader, [42u8; 32]);
        let mut follower = DEAP::new(Role::Follower, [69u8; 32]);

        let circ = adder_circ();

        let a = 1u8;
        let b = 2u8;
        let c: Value = (a + b).into();

        let leader_fut = {
            let (mut sink, mut stream) = leader_channel.split();
            let circ = circ.clone();
            let a_ref = leader.new_private_input("a", Some(a)).unwrap();
            let b_ref = leader.new_private_input::<u8>("b", None).unwrap();
            let c_ref = leader.new_output::<u8>("c").unwrap();

            async move {
                leader
                    .execute(
                        "test",
                        circ,
                        &[a_ref, b_ref],
                        &[c_ref.clone()],
                        &mut sink,
                        &mut stream,
                        &leader_ot_send,
                        &leader_ot_recv,
                    )
                    .await
                    .unwrap();

                let outputs = leader
                    .decode_private(
                        "test",
                        &[c_ref],
                        &mut sink,
                        &mut stream,
                        &leader_ot_send,
                        &leader_ot_recv,
                    )
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

            let a_ref = follower.new_private_input::<u8>("a", None).unwrap();
            let b_ref = follower.new_private_input("b", Some(b)).unwrap();
            let c_ref = follower.new_output::<u8>("c").unwrap();

            async move {
                follower
                    .execute(
                        "test",
                        circ.clone(),
                        &[a_ref, b_ref],
                        &[c_ref.clone()],
                        &mut sink,
                        &mut stream,
                        &follower_ot_send,
                        &follower_ot_recv,
                    )
                    .await
                    .unwrap();

                let outputs = follower
                    .decode_blind(
                        "test",
                        &[c_ref],
                        &mut sink,
                        &mut stream,
                        &follower_ot_send,
                        &follower_ot_recv,
                    )
                    .await
                    .unwrap();

                follower
                    .finalize(&mut sink, &mut stream, &follower_ot_recv)
                    .await
                    .unwrap();

                outputs
            }
        };

        let (leader_output, _) = tokio::join!(leader_fut, follower_fut);

        assert_eq!(leader_output, vec![c]);
    }

    #[tokio::test]
    async fn test_deap_decode_shared() {
        let (leader_channel, follower_channel) = DuplexChannel::<GarbleMessage>::new();
        let (leader_ot_send, follower_ot_recv) = mock_ot_pair();
        let (follower_ot_send, leader_ot_recv) = mock_ot_pair();

        let mut leader = DEAP::new(Role::Leader, [42u8; 32]);
        let mut follower = DEAP::new(Role::Follower, [69u8; 32]);

        let circ = adder_circ();

        let a = 1u8;
        let b = 2u8;
        let c = a + b;

        let leader_fut = {
            let (mut sink, mut stream) = leader_channel.split();
            let circ = circ.clone();
            let a_ref = leader.new_private_input("a", Some(a)).unwrap();
            let b_ref = leader.new_private_input::<u8>("b", None).unwrap();
            let c_ref = leader.new_output::<u8>("c").unwrap();

            async move {
                leader
                    .execute(
                        "test",
                        circ,
                        &[a_ref, b_ref],
                        &[c_ref.clone()],
                        &mut sink,
                        &mut stream,
                        &leader_ot_send,
                        &leader_ot_recv,
                    )
                    .await
                    .unwrap();

                let outputs = leader
                    .decode_shared(
                        "test",
                        &[c_ref],
                        &mut sink,
                        &mut stream,
                        &leader_ot_send,
                        &leader_ot_recv,
                    )
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

            let a_ref = follower.new_private_input::<u8>("a", None).unwrap();
            let b_ref = follower.new_private_input("b", Some(b)).unwrap();
            let c_ref = follower.new_output::<u8>("c").unwrap();

            async move {
                follower
                    .execute(
                        "test",
                        circ.clone(),
                        &[a_ref, b_ref],
                        &[c_ref.clone()],
                        &mut sink,
                        &mut stream,
                        &follower_ot_send,
                        &follower_ot_recv,
                    )
                    .await
                    .unwrap();

                let outputs = follower
                    .decode_shared(
                        "test",
                        &[c_ref],
                        &mut sink,
                        &mut stream,
                        &follower_ot_send,
                        &follower_ot_recv,
                    )
                    .await
                    .unwrap();

                follower
                    .finalize(&mut sink, &mut stream, &follower_ot_recv)
                    .await
                    .unwrap();

                outputs
            }
        };

        let (mut leader_output, mut follower_output) = tokio::join!(leader_fut, follower_fut);

        let leader_share: u8 = leader_output.pop().unwrap().try_into().unwrap();
        let follower_share: u8 = follower_output.pop().unwrap().try_into().unwrap();

        assert_eq!((leader_share ^ follower_share), c);
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
                    .defer_prove(
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
                    .defer_verify(
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
