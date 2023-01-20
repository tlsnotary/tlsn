use aes::{Aes128, NewBlockCipher};
use cipher::{consts::U16, BlockCipher, BlockEncrypt};
use std::{collections::HashSet, sync::Arc};

use crate::{
    block::Block,
    garble::{
        evaluator::evaluate,
        generator::garble,
        label::{
            decode_active_labels, extract_active_labels, extract_full_labels, ActiveInputLabels,
            ActiveInputLabelsSet, ActiveOutputLabels, ActiveOutputLabelsSet, FullInputLabels,
            FullOutputLabels, FullOutputLabelsSet, InputLabelsDecodingInfo, OutputLabelsCommitment,
            OutputLabelsDecodingInfo,
        },
        Delta, Error, LabelError,
    },
    utils::blake3,
};
use mpc_circuits::{Circuit, CircuitId, OutputValue};

/// Encrypted gate truth table
///
/// For the half-gate garbling scheme a truth table will typically have 2 rows, except for in
/// privacy-free garbling mode where it will be reduced to 1
#[derive(Debug, Clone, PartialEq)]
pub struct EncryptedGate([Block; 2]);

impl EncryptedGate {
    pub(crate) fn new(inner: [Block; 2]) -> Self {
        Self(inner)
    }
}

impl AsRef<[Block; 2]> for EncryptedGate {
    fn as_ref(&self) -> &[Block; 2] {
        &self.0
    }
}

fn gates_digest(encrypted_gates: &[EncryptedGate]) -> Vec<u8> {
    blake3(
        &encrypted_gates
            .iter()
            .map(|gate| gate.0)
            .flatten()
            .map(|gate| gate.to_be_bytes())
            .flatten()
            .collect::<Vec<u8>>(),
    )
    .to_vec()
}

/// All the various states of a garbled circuit
pub mod state {
    use super::*;

    mod sealed {
        use super::*;

        pub trait Sealed {}

        impl Sealed for Full {}
        impl Sealed for FullSummary {}
        impl Sealed for Partial {}
        impl Sealed for Evaluated {}
        impl Sealed for EvaluatedSummary {}
        impl Sealed for Compressed {}
        impl Sealed for Output {}
    }

    /// Marker trait for the state of a garbled circuit
    pub trait State: sealed::Sealed {}

    /// Full garbled circuit data. This includes all wire label pairs, encrypted gates and delta.
    #[derive(Debug)]
    pub struct Full {
        pub(crate) input_labels: FullInputLabelsSet,
        pub(crate) output_labels: FullOutputLabelsSet,
        /// Encrypted gates sorted ascending by id
        pub(crate) encrypted_gates: Vec<EncryptedGate>,
        #[allow(dead_code)]
        pub(crate) delta: Delta,
    }

    /// Summary of full garbled circuit data, only including input/output labels and decoding info.
    #[derive(Debug)]
    pub struct FullSummary {
        pub(crate) input_labels: FullInputLabelsSet,
        pub(crate) output_labels: FullOutputLabelsSet,
        /// Output labels decoding sorted ascending by id
        pub(crate) decoding: Vec<OutputLabelsDecodingInfo>,
        pub(crate) delta: Delta,
    }

    /// Garbled circuit data, optionally including the output decoding
    /// and or output label commitments.
    #[derive(Debug)]
    pub struct Partial {
        /// Encrypted gates sorted ascending by id
        pub(crate) encrypted_gates: Vec<EncryptedGate>,
        /// Output labels decoding sorted ascending by id
        pub(crate) decoding: Option<Vec<OutputLabelsDecodingInfo>>,
        /// Output label commitments sorted ascending by id
        pub(crate) commitments: Option<Vec<OutputLabelsCommitment>>,
    }

    /// Evaluated garbled circuit data
    #[derive(Debug, Clone)]
    pub struct Evaluated {
        pub(crate) input_labels: ActiveInputLabelsSet,
        pub(crate) output_labels: ActiveOutputLabelsSet,
        /// Encrypted gates sorted ascending by id
        pub(crate) encrypted_gates: Vec<EncryptedGate>,
        /// Output labels decoding sorted ascending by id
        pub(crate) decoding: Option<Vec<OutputLabelsDecodingInfo>>,
        /// Output label commitments sorted ascending by id
        pub(crate) commitments: Option<Vec<OutputLabelsCommitment>>,
    }

    /// Summary of evaluated garbled circuit data
    #[derive(Debug, Clone)]
    pub struct EvaluatedSummary {
        pub(crate) input_labels: ActiveInputLabelsSet,
        pub(crate) output_labels: ActiveOutputLabelsSet,
        /// Output labels decoding sorted ascending by id
        pub(crate) decoding: Option<Vec<OutputLabelsDecodingInfo>>,
    }

    /// Evaluated garbled circuit that has been compressed to minimize memory footprint
    #[derive(Debug, Clone)]
    pub struct Compressed {
        pub(crate) input_labels: ActiveInputLabelsSet,
        pub(crate) output_labels: ActiveOutputLabelsSet,
        /// Input labels plus the encrypted gates is what constitutes a garbled circuit (GC).
        /// In scenarios where we expect the generator to prove their honest GC generation,
        /// even after performing the evaluation, we want the evaluator to keep the GC around
        /// in order to compare it against an honestly generated circuit. To reduce the memory
        /// footprint, we keep a hash digest of the encrypted gates.
        pub(crate) gates_digest: Vec<u8>,
        /// Output labels decoding sorted ascending by id
        pub(crate) decoding: Option<Vec<OutputLabelsDecodingInfo>>,
        /// Output label commitments sorted ascending by id
        pub(crate) commitments: Option<Vec<OutputLabelsCommitment>>,
    }

    /// Evaluated garbled circuit output data
    #[derive(Debug)]
    pub struct Output {
        pub(crate) output_labels: ActiveOutputLabelsSet,
        /// Output labels decoding sorted ascending by id
        pub(crate) decoding: Option<Vec<OutputLabelsDecodingInfo>>,
    }

    impl State for Full {}
    impl State for FullSummary {}
    impl State for Partial {}
    impl State for Evaluated {}
    impl State for EvaluatedSummary {}
    impl State for Compressed {}
    impl State for Output {}
}

use state::*;

use super::label::FullInputLabelsSet;

/// Primary data structure for a garbled circuit with typed states found in [`state`]
#[derive(Debug, Clone)]
pub struct GarbledCircuit<S: State> {
    pub circ: Arc<Circuit>,
    pub(crate) state: S,
}

/// Data used for opening a garbled circuit (GC) to the evaluator.
/// To enable the evaluator to check that a GC was generated correctly, the generator
/// "opens" the GC.
/// We rely on the property of the "half-gates" garbling scheme that given the input
/// label pairs and the delta, a GC will always be generated deterministically.
/// We assume that the evaluator is already in posession of their active input labels.
#[derive(Debug, Clone)]
pub struct CircuitOpening {
    pub(crate) delta: Delta,
    pub(crate) input_decoding: Vec<InputLabelsDecodingInfo>,
}

impl CircuitOpening {
    /// Returns delta
    pub fn get_delta(&self) -> Delta {
        self.delta
    }

    /// Returns reference to input labels decoding info
    pub fn get_decoding(&self) -> &[InputLabelsDecodingInfo] {
        &self.input_decoding
    }
}

impl GarbledCircuit<Full> {
    /// Generate a garbled circuit with the provided input labels and delta.
    pub fn generate<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
        cipher: &C,
        circ: Arc<Circuit>,
        input_labels: FullInputLabelsSet,
    ) -> Result<Self, Error> {
        let (labels, encrypted_gates) = garble(cipher, &circ, input_labels.clone())?;

        let delta = input_labels.delta();

        let output_labels = extract_full_labels(circ.outputs(), delta, &labels);

        Ok(Self {
            circ,
            state: Full {
                input_labels,
                output_labels: FullOutputLabelsSet::new(output_labels)?,
                encrypted_gates,
                delta,
            },
        })
    }

    /// Returns output label decoding info
    pub(crate) fn decoding(&self) -> Vec<OutputLabelsDecodingInfo> {
        self.output_labels()
            .iter()
            .map(|labels| labels.decoding())
            .collect()
    }

    /// Returns output label commitments. To protect against the Evaluator using these
    /// commitments to decode their output, we shuffle them.
    pub(crate) fn output_commitments(&self) -> Vec<OutputLabelsCommitment> {
        self.output_labels()
            .iter()
            .map(|labels| labels.commit())
            .collect()
    }

    /// Returns reference to input labels set
    pub fn input_labels(&self) -> &FullInputLabelsSet {
        &self.state.input_labels
    }

    /// Returns reference to output labels set
    pub fn output_labels(&self) -> &FullOutputLabelsSet {
        &self.state.output_labels
    }

    /// Returns [`GarbledCircuit<Partial>`] which is safe to send an evaluator
    ///
    /// `reveal` flag determines whether the output decoding will be included
    /// `commit` flag determines whether commitments to the output labels will be included
    pub fn get_partial(
        &self,
        reveal: bool,
        commit: bool,
    ) -> Result<GarbledCircuit<Partial>, Error> {
        Ok(GarbledCircuit {
            circ: self.circ.clone(),
            state: Partial {
                encrypted_gates: self.state.encrypted_gates.clone(),
                decoding: reveal.then(|| self.decoding()),
                commitments: commit.then(|| self.output_commitments()),
            },
        })
    }

    /// Summarizes garbled circuit data to reduce memory footprint
    pub fn summarize(self) -> GarbledCircuit<FullSummary> {
        let decoding = self.decoding();
        let input_labels = self.state.input_labels;
        let output_labels = self.state.output_labels;
        let delta = self.state.delta;

        GarbledCircuit {
            circ: self.circ,
            state: FullSummary {
                input_labels,
                output_labels,
                decoding,
                delta,
            },
        }
    }

    /// Returns circuit opening
    pub fn open(&self) -> CircuitOpening {
        CircuitOpening {
            delta: self.state.delta,
            input_decoding: self
                .input_labels()
                .iter()
                .map(|labels| labels.decoding())
                .collect(),
        }
    }
}

impl GarbledCircuit<FullSummary> {
    /// Returns reference to input labels set
    pub fn input_labels(&self) -> &FullInputLabelsSet {
        &self.state.input_labels
    }

    /// Returns reference to output labels set
    pub fn output_labels(&self) -> &FullOutputLabelsSet {
        &self.state.output_labels
    }

    /// Returns output label decoding info if available
    pub fn decoding(&self) -> &[OutputLabelsDecodingInfo] {
        &self.state.decoding
    }

    /// Returns circuit opening
    pub fn open(&self) -> CircuitOpening {
        CircuitOpening {
            delta: self.state.delta,
            input_decoding: self
                .state
                .input_labels
                .get_labels()
                .iter()
                .map(|labels| labels.decoding())
                .collect(),
        }
    }
}

impl GarbledCircuit<Partial> {
    /// Returns whether or not output decoding info is available
    pub fn has_decoding(&self) -> bool {
        self.state.decoding.is_some()
    }

    /// Returns whether or not output label commitments were provided
    pub fn has_output_commitments(&self) -> bool {
        self.state.commitments.is_some()
    }

    /// Evaluates a garbled circuit using provided input labels. These labels are combined with labels sent by the generator
    /// and checked for correctness using the circuit spec.
    pub fn evaluate<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
        self,
        cipher: &C,
        input_labels: ActiveInputLabelsSet,
    ) -> Result<GarbledCircuit<Evaluated>, Error> {
        let labels = evaluate(
            cipher,
            &self.circ,
            input_labels.clone(),
            &self.state.encrypted_gates,
        )?;

        let output_labels = extract_active_labels(self.circ.outputs(), &labels);

        // Always check output labels against commitments if they're available
        if let Some(output_commitments) = self.state.commitments.as_ref() {
            output_commitments
                .iter()
                .zip(&output_labels)
                .map(|(commitment, labels)| commitment.validate(&labels))
                .collect::<Result<(), LabelError>>()?;
        }

        Ok(GarbledCircuit {
            circ: self.circ.clone(),
            state: Evaluated {
                input_labels,
                encrypted_gates: self.state.encrypted_gates,
                output_labels: ActiveOutputLabelsSet::new(output_labels)?,
                decoding: self.state.decoding,
                commitments: self.state.commitments,
            },
        })
    }
}

impl GarbledCircuit<Evaluated> {
    /// Returns all active inputs labels used to evaluate the circuit
    pub fn input_labels(&self) -> &ActiveInputLabelsSet {
        &self.state.input_labels
    }

    /// Returns all active output labels which are the result of circuit evaluation
    pub fn output_labels(&self) -> &ActiveOutputLabelsSet {
        &self.state.output_labels
    }

    /// Returns whether or not output decoding info is available
    pub fn has_decoding(&self) -> bool {
        self.state.decoding.is_some()
    }

    /// Returns whether or not output label commitments were provided
    pub fn has_output_commitments(&self) -> bool {
        self.state.commitments.is_some()
    }

    /// Returns garbled circuit output
    pub fn get_output(&self) -> GarbledCircuit<Output> {
        GarbledCircuit {
            circ: self.circ.clone(),
            state: Output {
                output_labels: self.state.output_labels.clone(),
                decoding: self.state.decoding.clone(),
            },
        }
    }

    /// Returns garbled circuit output, consumes self
    pub fn into_output(self) -> GarbledCircuit<Output> {
        GarbledCircuit {
            circ: self.circ.clone(),
            state: Output {
                output_labels: self.state.output_labels,
                decoding: self.state.decoding,
            },
        }
    }

    /// Returns a compressed evaluated circuit to reduce memory utilization
    pub fn into_compressed(self) -> GarbledCircuit<Compressed> {
        GarbledCircuit {
            circ: self.circ,
            state: Compressed {
                input_labels: self.state.input_labels,
                gates_digest: gates_digest(&self.state.encrypted_gates),
                output_labels: self.state.output_labels,
                decoding: self.state.decoding,
                commitments: self.state.commitments,
            },
        }
    }

    /// Returns a summary of the evaluated circuit to reduce memory utilization
    pub fn get_summary(&self) -> GarbledCircuit<EvaluatedSummary> {
        GarbledCircuit {
            circ: self.circ.clone(),
            state: EvaluatedSummary {
                input_labels: self.state.input_labels.clone(),
                output_labels: self.state.output_labels.clone(),
                decoding: self.state.decoding.clone(),
            },
        }
    }

    /// Returns a summary of the evaluated circuit to reduce memory utilization,
    /// consumes self
    pub fn into_summary(self) -> GarbledCircuit<EvaluatedSummary> {
        GarbledCircuit {
            circ: self.circ,
            state: EvaluatedSummary {
                input_labels: self.state.input_labels,
                output_labels: self.state.output_labels,
                decoding: self.state.decoding,
            },
        }
    }

    /// Returns decoded circuit outputs
    pub fn decode(&self) -> Result<Vec<OutputValue>, Error> {
        let decoding = self.state.decoding.as_ref().ok_or(Error::MissingDecoding)?;
        decode_active_labels(self.output_labels().get_labels(), decoding).map_err(Error::from)
    }

    /// Validates circuit using [`CircuitOpening`]
    pub fn validate(&self, opening: CircuitOpening) -> Result<(), Error> {
        validate_circuit(
            &Aes128::new_from_slice(&[0; 16]).unwrap(),
            &self.circ,
            opening,
            &self.state.input_labels.get_labels(),
            Some(self.state.encrypted_gates.as_slice()),
            None,
            self.state.decoding.as_ref().map(Vec::as_slice),
            self.state.commitments.as_ref().map(Vec::as_slice),
        )
    }
}

impl GarbledCircuit<EvaluatedSummary> {
    /// Returns reference to input labels set
    pub fn input_labels(&self) -> &ActiveInputLabelsSet {
        &self.state.input_labels
    }

    /// Returns reference to output labels set
    pub fn output_labels(&self) -> &ActiveOutputLabelsSet {
        &self.state.output_labels
    }

    /// Returns whether or not output decoding info is available
    pub fn has_decoding(&self) -> bool {
        self.state.decoding.is_some()
    }

    /// Returns decoded circuit outputs
    pub fn decode(&self) -> Result<Vec<OutputValue>, Error> {
        let decoding = self.state.decoding.as_ref().ok_or(Error::MissingDecoding)?;
        decode_active_labels(self.output_labels().get_labels(), decoding).map_err(Error::from)
    }
}

impl GarbledCircuit<Compressed> {
    /// Returns all active inputs labels used to evaluate the circuit
    pub fn input_labels(&self) -> &ActiveInputLabelsSet {
        &self.state.input_labels
    }

    /// Returns all active output labels which are the result of circuit evaluation
    pub fn output_labels(&self) -> &ActiveOutputLabelsSet {
        &self.state.output_labels
    }

    /// Returns whether or not output decoding info is available
    pub fn has_decoding(&self) -> bool {
        self.state.decoding.is_some()
    }

    /// Returns garbled circuit output
    pub fn get_output(&self) -> GarbledCircuit<Output> {
        GarbledCircuit {
            circ: self.circ.clone(),
            state: Output {
                output_labels: self.state.output_labels.clone(),
                decoding: self.state.decoding.clone(),
            },
        }
    }

    /// Returns decoded circuit outputs
    pub fn decode(&self) -> Result<Vec<OutputValue>, Error> {
        let decoding = self.state.decoding.as_ref().ok_or(Error::MissingDecoding)?;
        decode_active_labels(self.output_labels().get_labels(), decoding).map_err(Error::from)
    }

    /// Validates circuit using [`CircuitOpening`]
    pub fn validate(&self, opening: CircuitOpening) -> Result<(), Error> {
        validate_circuit(
            &Aes128::new_from_slice(&[0; 16]).unwrap(),
            &self.circ,
            opening,
            &self.state.input_labels.get_labels(),
            None,
            Some(self.state.gates_digest.clone()),
            self.state.decoding.as_ref().map(Vec::as_slice),
            self.state.commitments.as_ref().map(Vec::as_slice),
        )
    }
}

impl GarbledCircuit<Output> {
    /// Returns all output labels
    pub fn output_labels(&self) -> &ActiveOutputLabelsSet {
        &self.state.output_labels
    }

    /// Returns whether or not output decoding info is available
    pub fn has_decoding(&self) -> bool {
        self.state.decoding.is_some()
    }

    /// Returns output label decoding info if available
    pub fn decoding(&self) -> Option<Vec<OutputLabelsDecodingInfo>> {
        self.state.decoding.clone()
    }

    /// Returns decoded circuit outputs
    pub fn decode(&self) -> Result<Vec<OutputValue>, Error> {
        let decoding = self.state.decoding.as_ref().ok_or(Error::MissingDecoding)?;
        decode_active_labels(self.output_labels().get_labels(), decoding).map_err(Error::from)
    }
}

fn validate_circuit<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
    cipher: &C,
    circ: &Circuit,
    opening: CircuitOpening,
    input_labels: &[ActiveInputLabels],
    encrypted_gates: Option<&[EncryptedGate]>,
    digest: Option<Vec<u8>>,
    output_decoding: Option<&[OutputLabelsDecodingInfo]>,
    output_commitments: Option<&[OutputLabelsCommitment]>,
) -> Result<(), Error> {
    let CircuitOpening {
        delta,
        input_decoding,
        ..
    } = opening;

    let full_input_labels = input_labels
        .iter()
        .zip(input_decoding)
        .map(|(labels, decoding)| FullInputLabels::from_decoding(labels.clone(), delta, decoding))
        .collect::<Result<Vec<_>, LabelError>>()?;

    let full_input_labels = FullInputLabelsSet::new(full_input_labels)?;

    let digest = if let Some(encrypted_gates) = encrypted_gates {
        // If gates are passed in, hash them
        gates_digest(encrypted_gates)
    } else if let Some(digest) = digest {
        // Otherwise if the digest was already computed, use that instead.
        digest
    } else {
        return Err(Error::General(
            "Must provide encrypted gates or digest".to_string(),
        ));
    };

    // Re-garble circuit using input labels.
    // We rely on the property of the "half-gates" garbling scheme that given the input
    // labels, the encrypted gates will always be computed deterministically.
    let (labels, encrypted_gates) = garble(cipher, circ, full_input_labels)?;

    // Compute the expected gates digest
    let expected_digest = gates_digest(&encrypted_gates);

    // If hashes don't match circuit wasn't garbled correctly
    if expected_digest != digest {
        return Err(Error::CorruptedGarbledCircuit);
    }

    // Check output decoding info if it was sent
    if let Some(output_decoding) = output_decoding {
        let expected_output_decoding: Vec<OutputLabelsDecodingInfo> =
            extract_full_labels(circ.outputs(), delta, &labels)
                .into_iter()
                .map(|labels| labels.decoding())
                .collect();

        if &expected_output_decoding != output_decoding {
            return Err(Error::CorruptedGarbledCircuit);
        }
    }

    // Check output commitments if they were sent
    if let Some(output_commitments) = output_commitments {
        let expected_output_commitments: Vec<OutputLabelsCommitment> =
            extract_full_labels(circ.outputs(), delta, &labels)
                .into_iter()
                .map(|labels| labels.commit())
                .collect();

        if &expected_output_commitments != output_commitments {
            return Err(Error::CorruptedGarbledCircuit);
        }
    }

    Ok(())
}

pub(crate) mod unchecked {
    use utils::iter::DuplicateCheckBy;

    use super::*;

    use crate::garble::label::{output::unchecked::*, unchecked::*};

    /// Partial garbled circuit which has not been validated against a circuit spec
    #[derive(Debug, Clone)]
    pub struct UncheckedGarbledCircuit {
        pub(crate) id: String,
        pub(crate) encrypted_gates: Vec<Block>,
        pub(crate) decoding: Option<Vec<UncheckedLabelsDecodingInfo>>,
        pub(crate) commitments: Option<Vec<UncheckedOutputLabelsCommitment>>,
    }

    #[cfg(test)]
    impl From<GarbledCircuit<Partial>> for UncheckedGarbledCircuit {
        fn from(gc: GarbledCircuit<Partial>) -> Self {
            Self {
                id: gc.circ.id().clone().to_string(),
                encrypted_gates: gc
                    .state
                    .encrypted_gates
                    .into_iter()
                    .map(|gate| gate.0)
                    .flatten()
                    .collect(),
                decoding: gc.state.decoding.map(|decodings| {
                    decodings
                        .into_iter()
                        .map(UncheckedLabelsDecodingInfo::from)
                        .collect()
                }),
                commitments: gc.state.commitments.map(|commitments| {
                    commitments
                        .into_iter()
                        .map(UncheckedOutputLabelsCommitment::from)
                        .collect()
                }),
            }
        }
    }

    impl GarbledCircuit<Partial> {
        pub fn from_unchecked(
            circ: Arc<Circuit>,
            unchecked: UncheckedGarbledCircuit,
        ) -> Result<Self, Error> {
            let circ_id = CircuitId::new(unchecked.id)?;
            // Validate circuit id
            if &circ_id != circ.id() {
                return Err(Error::ValidationError(format!(
                    "Wrong circuit id: expected {}, received {}",
                    circ.id().as_ref(),
                    circ_id.to_string()
                )));
            }

            // Make sure the expected number of gates is present. In half-gates garbling each
            // AND gate is encrypted into 2 block-sized ciphertexts.
            if unchecked.encrypted_gates.len() != 2 * circ.and_count() {
                return Err(Error::ValidationError(
                    "Incorrect number of encrypted gates".to_string(),
                ));
            }

            // Convert encrypted gates to typed version
            let encrypted_gates = unchecked
                .encrypted_gates
                .chunks_exact(2)
                .into_iter()
                .map(|gate| EncryptedGate::new([gate[0], gate[1]]))
                .collect();

            // Validate output decoding info
            let decoding = match unchecked.decoding {
                Some(mut decoding) => {
                    // Check for duplicates
                    if decoding.iter().contains_dups_by(|decoding| &decoding.id) {
                        return Err(Error::ValidationError(
                            "Duplicate output decoding".to_string(),
                        ));
                    }

                    // Make sure decodings are sorted by id
                    decoding.sort_by_key(|decoding| decoding.id);

                    // Check for unexpected output ids
                    if !decoding
                        .iter()
                        .map(|decoding| decoding.id)
                        .all(|id| circ.is_input_id(id))
                    {
                        return Err(Error::ValidationError(
                            "Invalid decoding output id".to_string(),
                        ));
                    }

                    // Check that all output decodings are present
                    // NOTE: we may relax this requirement in the future
                    if decoding.len() != circ.output_count() {
                        return Err(Error::ValidationError(
                            "Incorrect number of output decodings".to_string(),
                        ));
                    }

                    Some(
                        decoding
                            .into_iter()
                            .zip(circ.outputs())
                            .map(|(unchecked, output)| {
                                OutputLabelsDecodingInfo::from_unchecked(output.clone(), unchecked)
                            })
                            .collect::<Result<Vec<_>, LabelError>>()
                            .map_err(Error::from)?,
                    )
                }
                None => None,
            };

            let commitments = match unchecked.commitments {
                Some(mut commitments) => {
                    // Check for duplicates
                    if commitments
                        .iter()
                        .contains_dups_by(|commitment| &commitment.id)
                    {
                        return Err(Error::ValidationError("Duplicate commitments".to_string()));
                    }

                    // Make sure decodings are sorted by id
                    commitments.sort_by_key(|decoding| decoding.id);

                    // Check for unexpected output ids
                    if !commitments
                        .iter()
                        .map(|commitment| commitment.id)
                        .all(|id| circ.is_input_id(id))
                    {
                        return Err(Error::ValidationError(
                            "Invalid commitment output id".to_string(),
                        ));
                    }

                    // Check that all output commitments are present
                    // NOTE: we may relax this requirement in the future
                    if commitments.len() != circ.output_count() {
                        return Err(Error::ValidationError(
                            "Incorrect number of output decodings".to_string(),
                        ));
                    }

                    Some(
                        commitments
                            .into_iter()
                            .zip(circ.outputs())
                            .map(|(unchecked, output)| {
                                OutputLabelsCommitment::from_unchecked(output.clone(), unchecked)
                            })
                            .collect::<Result<Vec<_>, Error>>()?,
                    )
                }
                None => None,
            };

            Ok(Self {
                circ,
                state: Partial {
                    encrypted_gates,
                    decoding,
                    commitments,
                },
            })
        }
    }

    /// Output of a garbled circuit which has not been validated
    #[derive(Debug, Clone)]
    pub struct UncheckedOutput {
        pub(crate) circ_id: String,
        pub(crate) output_labels: Vec<UncheckedOutputLabels>,
    }

    #[cfg(test)]
    impl From<GarbledCircuit<Output>> for UncheckedOutput {
        fn from(gc: GarbledCircuit<Output>) -> Self {
            Self {
                circ_id: gc.circ.id().clone().to_string(),
                output_labels: gc
                    .state
                    .output_labels
                    .to_inner()
                    .into_iter()
                    .map(UncheckedOutputLabels::from)
                    .collect(),
            }
        }
    }

    impl UncheckedOutput {
        /// Validates and decodes output using circuit spec and full output labels
        pub fn decode(
            mut self,
            circ: &Circuit,
            full_output_labels: &[FullOutputLabels],
        ) -> Result<Vec<OutputValue>, Error> {
            let circ_id = CircuitId::new(self.circ_id)?;
            // Validate circuit id
            if &circ_id != circ.id() {
                return Err(Error::ValidationError(format!(
                    "Received garbled output with wrong id: expected {}, received {}",
                    circ.id().as_ref(),
                    circ_id.to_string()
                )));
            }

            // Check for duplicates
            let output_ids: HashSet<usize> =
                self.output_labels.iter().map(|output| output.id).collect();

            if output_ids.len() != self.output_labels.len() {
                return Err(Error::ValidationError(
                    "Received garbled output with duplicates".to_string(),
                ));
            }

            // Make sure outputs are sorted
            self.output_labels
                .sort_by_key(|output_label| output_label.id);

            // Check all outputs were received
            if self.output_labels.len() != circ.output_count() {
                return Err(Error::ValidationError(format!(
                    "Received garbled output with wrong number of outputs: expected {}, received {}",
                    circ.output_count(),
                    self.output_labels.len()
                )));
            }

            let output_labels = self
                .output_labels
                .into_iter()
                .map(|labels| ActiveOutputLabels::from_unchecked(&circ, labels))
                .collect::<Result<Vec<_>, _>>()?;

            // Validates that each output label is authentic then decodes them
            full_output_labels
                .iter()
                .zip(&output_labels)
                .map(|(full, ev)| {
                    full.validate(ev)?;
                    ev.decode(full.decoding().clone())
                })
                .collect::<Result<Vec<_>, LabelError>>()
                .map_err(Error::from)
        }
    }

    /// Unchecked variant of [`CircuitOpening`]
    #[derive(Debug, Clone)]
    pub struct UncheckedCircuitOpening {
        pub(crate) delta: Delta,
        pub(crate) input_decoding: Vec<UncheckedLabelsDecodingInfo>,
    }

    #[cfg(test)]
    impl From<CircuitOpening> for UncheckedCircuitOpening {
        fn from(opening: CircuitOpening) -> Self {
            Self {
                delta: opening.delta,
                input_decoding: opening
                    .input_decoding
                    .into_iter()
                    .map(UncheckedLabelsDecodingInfo::from)
                    .collect(),
            }
        }
    }

    impl CircuitOpening {
        /// Validates opening data and converts to checked variant [`CircuitOpening`]
        pub fn from_unchecked(
            circ: &Circuit,
            unchecked: UncheckedCircuitOpening,
        ) -> Result<Self, Error> {
            let UncheckedCircuitOpening {
                delta,
                mut input_decoding,
            } = unchecked;

            // Sort by input id
            input_decoding.sort_by_key(|decoding| decoding.id);

            // 1. Check for duplicates
            // 2. Check all decodings are present
            // 3. Check all input ids are valid
            if input_decoding
                .iter()
                .contains_dups_by(|decoding| &decoding.id)
                || input_decoding.len() != circ.input_count()
                || !input_decoding
                    .iter()
                    .all(|decoding| circ.is_input_id(decoding.id))
            {
                return Err(Error::InvalidOpening);
            }

            // Convert unchecked decodings to checked variant
            let input_decoding = input_decoding
                .into_iter()
                .zip(circ.inputs())
                .map(|(unchecked, input)| {
                    InputLabelsDecodingInfo::from_unchecked(input.clone(), unchecked)
                })
                .collect::<Result<Vec<_>, LabelError>>()?;

            Ok(CircuitOpening {
                delta,
                input_decoding,
            })
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use aes::{Aes128, NewBlockCipher};
        use rand_chacha::ChaCha12Rng;
        use rand_core::SeedableRng;
        use rstest::*;

        use mpc_circuits::{Circuit, Input, WireGroup, ADDER_64, AES_128_REVERSE};

        #[fixture]
        fn circ() -> Arc<Circuit> {
            Circuit::load_bytes(ADDER_64).unwrap()
        }

        #[fixture]
        fn input(circ: Arc<Circuit>, #[default(0)] id: usize) -> Input {
            circ.input(id).unwrap()
        }

        #[fixture]
        fn garbled_circuit(circ: Arc<Circuit>) -> GarbledCircuit<Full> {
            let input_labels =
                FullInputLabelsSet::generate(&mut ChaCha12Rng::seed_from_u64(0), &circ, None);
            GarbledCircuit::generate(
                &Aes128::new_from_slice(&[0; 16]).unwrap(),
                circ,
                input_labels,
            )
            .unwrap()
        }

        #[fixture]
        fn unchecked_garbled_circuit(
            garbled_circuit: GarbledCircuit<Full>,
        ) -> UncheckedGarbledCircuit {
            garbled_circuit.get_partial(true, true).unwrap().into()
        }

        #[fixture]
        fn unchecked_garbled_output(
            #[default(&[(0, 0), (1, 0)])] inputs: &[(usize, u64)],
            garbled_circuit: GarbledCircuit<Full>,
        ) -> UncheckedOutput {
            let output_labels = garbled_circuit.output_labels().get_labels().to_vec();
            let circ = garbled_circuit.circ;

            let input_values: Vec<_> = inputs
                .iter()
                .copied()
                .map(|(id, value)| circ.input(id).unwrap().to_value(value).unwrap())
                .collect();

            let output_values = circ.evaluate(&input_values).unwrap();

            UncheckedOutput {
                circ_id: circ.id().clone().to_string(),
                output_labels: output_labels
                    .into_iter()
                    .zip(&output_values)
                    .map(|(labels, value)| labels.select(value.value()).unwrap().into())
                    .collect(),
            }
        }

        #[fixture]
        fn unchecked_opening(garbled_circuit: GarbledCircuit<Full>) -> UncheckedCircuitOpening {
            garbled_circuit.open().into()
        }

        #[rstest]
        fn test_unchecked_garbled_circuit(
            unchecked_garbled_circuit: UncheckedGarbledCircuit,
            circ: Arc<Circuit>,
        ) {
            GarbledCircuit::from_unchecked(circ, unchecked_garbled_circuit).unwrap();
        }

        #[rstest]
        fn test_unchecked_garbled_circuit_wrong_id(
            mut unchecked_garbled_circuit: UncheckedGarbledCircuit,
            circ: Arc<Circuit>,
        ) {
            unchecked_garbled_circuit.id = Circuit::load_bytes(AES_128_REVERSE)
                .unwrap()
                .id()
                .clone()
                .to_string();
            let err = GarbledCircuit::from_unchecked(circ, unchecked_garbled_circuit.clone())
                .unwrap_err();

            assert!(matches!(err, Error::ValidationError(_)));
        }

        #[rstest]
        fn test_unchecked_garbled_circuit_wrong_gate_count(
            mut unchecked_garbled_circuit: UncheckedGarbledCircuit,
            circ: Arc<Circuit>,
        ) {
            let circ = circ;
            unchecked_garbled_circuit
                .encrypted_gates
                .push(Block::new(0));
            let err =
                GarbledCircuit::from_unchecked(circ.clone(), unchecked_garbled_circuit.clone())
                    .unwrap_err();

            assert!(matches!(err, Error::ValidationError(_)));

            unchecked_garbled_circuit.encrypted_gates.pop();
            unchecked_garbled_circuit.encrypted_gates.pop();
            let err = GarbledCircuit::from_unchecked(circ, unchecked_garbled_circuit).unwrap_err();

            assert!(matches!(err, Error::ValidationError(_)));
        }

        #[rstest]
        fn test_unchecked_garbled_circuit_wrong_decoding_count(
            mut unchecked_garbled_circuit: UncheckedGarbledCircuit,
            circ: Arc<Circuit>,
        ) {
            let circ = circ;
            let dup = unchecked_garbled_circuit.decoding.as_ref().unwrap()[0].clone();
            unchecked_garbled_circuit
                .decoding
                .as_mut()
                .unwrap()
                .push(dup);

            let err =
                GarbledCircuit::from_unchecked(circ.clone(), unchecked_garbled_circuit.clone())
                    .unwrap_err();

            assert!(matches!(err, Error::ValidationError(_)));

            unchecked_garbled_circuit.decoding.as_mut().unwrap().pop();
            unchecked_garbled_circuit.decoding.as_mut().unwrap().pop();

            let err = GarbledCircuit::from_unchecked(circ, unchecked_garbled_circuit).unwrap_err();

            assert!(matches!(err, Error::ValidationError(_)));
        }

        #[rstest]
        fn test_unchecked_garbled_circuit_wrong_commitment_count(
            mut unchecked_garbled_circuit: UncheckedGarbledCircuit,
            circ: Arc<Circuit>,
        ) {
            let circ = circ;
            let dup = unchecked_garbled_circuit.commitments.as_ref().unwrap()[0].clone();
            unchecked_garbled_circuit
                .commitments
                .as_mut()
                .unwrap()
                .push(dup);

            let err =
                GarbledCircuit::from_unchecked(circ.clone(), unchecked_garbled_circuit.clone())
                    .unwrap_err();

            assert!(matches!(err, Error::ValidationError(_)));

            unchecked_garbled_circuit
                .commitments
                .as_mut()
                .unwrap()
                .pop();
            unchecked_garbled_circuit
                .commitments
                .as_mut()
                .unwrap()
                .pop();

            let err = GarbledCircuit::from_unchecked(circ, unchecked_garbled_circuit).unwrap_err();

            assert!(matches!(err, Error::ValidationError(_)));
        }

        #[rstest]
        fn test_unchecked_garbled_output(
            unchecked_garbled_output: UncheckedOutput,
            garbled_circuit: GarbledCircuit<Full>,
        ) {
            unchecked_garbled_output
                .decode(
                    &garbled_circuit.circ,
                    garbled_circuit.output_labels().get_labels(),
                )
                .unwrap();
        }

        #[rstest]
        fn test_unchecked_garbled_output_wrong_id(
            mut unchecked_garbled_output: UncheckedOutput,
            garbled_circuit: GarbledCircuit<Full>,
        ) {
            unchecked_garbled_output.circ_id = Circuit::load_bytes(AES_128_REVERSE)
                .unwrap()
                .id()
                .clone()
                .to_string();
            let err = unchecked_garbled_output
                .decode(
                    &garbled_circuit.circ,
                    garbled_circuit.output_labels().get_labels(),
                )
                .unwrap_err();

            assert!(matches!(err, Error::ValidationError(_)));
        }

        #[rstest]
        fn test_unchecked_garbled_output_corrupt_label(
            mut unchecked_garbled_output: UncheckedOutput,
            garbled_circuit: GarbledCircuit<Full>,
        ) {
            unchecked_garbled_output.output_labels[0].labels[0] = Block::new(0);
            let err = unchecked_garbled_output
                .decode(
                    &garbled_circuit.circ,
                    garbled_circuit.output_labels().get_labels(),
                )
                .unwrap_err();

            assert!(matches!(err, Error::LabelError(_)));
        }

        #[rstest]
        fn test_unchecked_garbled_output_wrong_label_count(
            mut unchecked_garbled_output: UncheckedOutput,
            garbled_circuit: GarbledCircuit<Full>,
        ) {
            unchecked_garbled_output.output_labels[0].labels.pop();
            let err = unchecked_garbled_output
                .decode(
                    &garbled_circuit.circ,
                    garbled_circuit.output_labels().get_labels(),
                )
                .unwrap_err();

            assert!(matches!(err, Error::LabelError(_)));
        }

        #[rstest]
        fn test_unchecked_garbled_output_wrong_output_count(
            mut unchecked_garbled_output: UncheckedOutput,
            garbled_circuit: GarbledCircuit<Full>,
        ) {
            unchecked_garbled_output.output_labels.pop();
            let err = unchecked_garbled_output
                .decode(
                    &garbled_circuit.circ,
                    garbled_circuit.output_labels().get_labels(),
                )
                .unwrap_err();

            assert!(matches!(err, Error::ValidationError(_)));
        }

        #[rstest]
        fn test_unchecked_garbled_output_duplicates(
            mut unchecked_garbled_output: UncheckedOutput,
            garbled_circuit: GarbledCircuit<Full>,
        ) {
            let dup = unchecked_garbled_output.output_labels[0].clone();
            unchecked_garbled_output.output_labels.push(dup);
            let err = unchecked_garbled_output
                .decode(
                    &garbled_circuit.circ,
                    garbled_circuit.output_labels().get_labels(),
                )
                .unwrap_err();

            assert!(matches!(err, Error::ValidationError(_)));
        }

        #[rstest]
        fn test_unchecked_opening(circ: Arc<Circuit>, unchecked_opening: UncheckedCircuitOpening) {
            CircuitOpening::from_unchecked(&circ, unchecked_opening).unwrap();
        }

        #[rstest]
        fn test_unchecked_opening_wrong_decoding_count(
            circ: Arc<Circuit>,
            mut unchecked_opening: UncheckedCircuitOpening,
        ) {
            unchecked_opening.input_decoding.pop();
            let err = CircuitOpening::from_unchecked(&circ, unchecked_opening).unwrap_err();

            assert!(matches!(err, Error::InvalidOpening))
        }
    }
}

#[cfg(test)]
mod tests {
    use aes::{Aes128, NewBlockCipher};
    use mpc_circuits::{WireGroup, AES_128_REVERSE};
    use rand_chacha::ChaCha12Rng;
    use rand_core::SeedableRng;

    use crate::garble::WireLabelPair;

    use super::*;

    #[test]
    fn test_circuit_validation_pass() {
        let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
        let mut rng = ChaCha12Rng::seed_from_u64(0);
        let circ = Circuit::load_bytes(AES_128_REVERSE).unwrap();

        let key = circ.input(0).unwrap().to_value(vec![0u8; 16]).unwrap();
        let msg = circ.input(1).unwrap().to_value(vec![0u8; 16]).unwrap();
        let input_labels = FullInputLabelsSet::generate(&mut rng, &circ, None);

        let gc = GarbledCircuit::generate(&cipher, circ.clone(), input_labels.clone()).unwrap();
        let opening = gc.open();

        let key_labels = input_labels[0].select(key.value()).unwrap();
        let msg_labels = input_labels[1].select(msg.value()).unwrap();

        let partial_gc = gc.get_partial(true, false).unwrap();
        let ev_gc = partial_gc
            .evaluate(
                &cipher,
                ActiveInputLabelsSet::new(vec![key_labels, msg_labels]).unwrap(),
            )
            .unwrap();

        ev_gc.validate(opening.clone()).unwrap();
        ev_gc.into_compressed().validate(opening).unwrap();
    }

    #[test]
    fn test_circuit_validation_fail_bad_gate() {
        let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
        let mut rng = ChaCha12Rng::seed_from_u64(0);
        let circ = Circuit::load_bytes(AES_128_REVERSE).unwrap();

        let key = circ.input(0).unwrap().to_value(vec![0u8; 16]).unwrap();
        let msg = circ.input(1).unwrap().to_value(vec![0u8; 16]).unwrap();
        let input_labels = FullInputLabelsSet::generate(&mut rng, &circ, None);

        let mut gc = GarbledCircuit::generate(&cipher, circ.clone(), input_labels.clone()).unwrap();
        let opening = gc.open();

        // set bogus gate
        gc.state.encrypted_gates[0].0[0] = Block::new(0);

        let key_labels = input_labels[0].select(key.value()).unwrap();
        let msg_labels = input_labels[1].select(msg.value()).unwrap();

        let partial_gc = gc.get_partial(true, false).unwrap();
        let ev_gc = partial_gc
            .evaluate(
                &cipher,
                ActiveInputLabelsSet::new(vec![key_labels, msg_labels]).unwrap(),
            )
            .unwrap();

        let err = ev_gc.validate(opening.clone()).unwrap_err();

        assert!(matches!(err, Error::CorruptedGarbledCircuit));

        let cmp_gc = ev_gc.into_compressed();

        let err = cmp_gc.validate(opening).unwrap_err();

        assert!(matches!(err, Error::CorruptedGarbledCircuit));
    }

    #[test]
    fn test_circuit_validation_fail_bad_input_label() {
        let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
        let mut rng = ChaCha12Rng::seed_from_u64(0);
        let circ = Circuit::load_bytes(AES_128_REVERSE).unwrap();

        let key = circ.input(0).unwrap().to_value(vec![0u8; 16]).unwrap();
        let msg = circ.input(1).unwrap().to_value(vec![0u8; 16]).unwrap();
        let mut input_labels = FullInputLabelsSet::generate(&mut rng, &circ, None);

        let gc = GarbledCircuit::generate(&cipher, circ.clone(), input_labels.clone()).unwrap();
        let opening = gc.open();

        // set bogus label
        input_labels[0].set(0, WireLabelPair::new(0, Block::new(0), Block::new(0)));

        let key_labels = input_labels[0].select(key.value()).unwrap();
        let msg_labels = input_labels[1].select(msg.value()).unwrap();

        let partial_gc = gc.get_partial(true, false).unwrap();
        let ev_gc = partial_gc
            .evaluate(
                &cipher,
                ActiveInputLabelsSet::new(vec![key_labels, msg_labels]).unwrap(),
            )
            .unwrap();

        let err = ev_gc.validate(opening.clone()).unwrap_err();

        assert!(matches!(err, Error::CorruptedGarbledCircuit));

        let cmp_gc = ev_gc.into_compressed();

        let err = cmp_gc.validate(opening).unwrap_err();

        assert!(matches!(err, Error::CorruptedGarbledCircuit));
    }

    #[test]
    /// The Generator sends invalid output label decoding info which causes the evaluator to
    /// derive incorrect output. Testing that this will be detected during validation.
    fn test_circuit_validation_fail_bad_output_decoding() {
        let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
        let mut rng = ChaCha12Rng::seed_from_u64(0);
        let circ = Circuit::load_bytes(AES_128_REVERSE).unwrap();

        let key = circ.input(0).unwrap().to_value(vec![0u8; 16]).unwrap();
        let msg = circ.input(1).unwrap().to_value(vec![0u8; 16]).unwrap();
        let input_labels = FullInputLabelsSet::generate(&mut rng, &circ, None);

        let mut gc = GarbledCircuit::generate(&cipher, circ.clone(), input_labels.clone()).unwrap();
        let opening = gc.open();

        // Flip output labels. This will cause the generator to compute
        // corrupted decoding info.
        gc.state.output_labels[0].flip(0);

        let key_labels = input_labels[0].select(key.value()).unwrap();
        let msg_labels = input_labels[1].select(msg.value()).unwrap();

        let partial_gc = gc.get_partial(true, true).unwrap();

        let ev_gc = partial_gc
            .evaluate(
                &cipher,
                ActiveInputLabelsSet::new(vec![key_labels, msg_labels]).unwrap(),
            )
            .unwrap();

        let err = ev_gc.validate(opening.clone()).unwrap_err();

        assert!(matches!(err, Error::CorruptedGarbledCircuit));

        let cmp_gc = ev_gc.into_compressed();

        let err = cmp_gc.validate(opening).unwrap_err();

        assert!(matches!(err, Error::CorruptedGarbledCircuit));
    }

    #[test]
    fn test_circuit_validation_fail_bad_output_commitment() {
        let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
        let mut rng = ChaCha12Rng::seed_from_u64(0);
        let circ = Circuit::load_bytes(AES_128_REVERSE).unwrap();

        let key = circ.input(0).unwrap().to_value(vec![0u8; 16]).unwrap();
        let msg = circ.input(1).unwrap().to_value(vec![0u8; 16]).unwrap();
        let mut input_labels = FullInputLabelsSet::generate(&mut rng, &circ, None);

        let gc = GarbledCircuit::generate(&cipher, circ.clone(), input_labels.clone()).unwrap();
        let opening = gc.open();

        // set bogus label (the opposite label the evaluator receives)
        // evaluation should pass but the circuit validation should fail because the commitment is bad
        let target_label = input_labels[0].get(0);
        input_labels[0].set(
            0,
            WireLabelPair::new(target_label.id(), target_label.low(), Block::new(0)),
        );

        let key_labels = input_labels[0].select(key.value()).unwrap();
        let msg_labels = input_labels[1].select(msg.value()).unwrap();

        let partial_gc = gc.get_partial(true, true).unwrap();
        let ev_gc = partial_gc
            .evaluate(
                &cipher,
                ActiveInputLabelsSet::new(vec![key_labels, msg_labels]).unwrap(),
            )
            .unwrap();

        let err = ev_gc.validate(opening.clone()).unwrap_err();

        assert!(matches!(err, Error::CorruptedGarbledCircuit));

        let cmp_gc = ev_gc.into_compressed();

        let err = cmp_gc.validate(opening).unwrap_err();

        assert!(matches!(err, Error::CorruptedGarbledCircuit));
    }
}
