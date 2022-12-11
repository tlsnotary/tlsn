use cipher::{consts::U16, BlockCipher, BlockEncrypt};
use std::{collections::HashSet, sync::Arc};

use crate::{
    block::Block,
    garble::{
        evaluator::evaluate,
        generator::garble,
        label::{
            decode_output_labels, extract_input_labels, extract_output_labels, OutputLabels,
            OutputLabelsCommitment, OutputLabelsDecodingInfo, SanitizedInputLabels,
        },
        Delta, Error, InputLabels, WireLabel, WireLabelPair,
    },
    utils::sha256,
};
use mpc_circuits::{Circuit, CircuitId, InputValue, OutputValue};

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
    sha256(
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
        impl Sealed for Summary {}
        impl Sealed for Partial {}
        impl Sealed for Evaluated {}
        impl Sealed for Compressed {}
        impl Sealed for Output {}
    }

    /// Marker trait for the state of a garbled circuit
    pub trait State: sealed::Sealed {}

    /// Full garbled circuit data. This includes all wire label pairs, encrypted gates and delta.
    #[derive(Debug)]
    pub struct Full {
        pub(crate) labels: Vec<WireLabelPair>,
        pub(crate) encrypted_gates: Vec<EncryptedGate>,
        #[allow(dead_code)]
        pub(crate) delta: Delta,
    }

    /// Summary of garbled circuit data, only including input/output labels and decoding info.
    #[derive(Debug)]
    pub struct Summary {
        pub(crate) input_labels: Vec<InputLabels<WireLabelPair>>,
        pub(crate) output_labels: Vec<OutputLabels<WireLabelPair>>,
        pub(crate) decoding: Vec<OutputLabelsDecodingInfo>,
    }

    /// Garbled circuit data including input labels from the generator and (optionally) the output decoding
    /// to reveal the plaintext output of the circuit.
    #[derive(Debug)]
    pub struct Partial {
        pub(crate) input_labels: Vec<InputLabels<WireLabel>>,
        pub(crate) encrypted_gates: Vec<EncryptedGate>,
        pub(crate) decoding: Option<Vec<OutputLabelsDecodingInfo>>,
        pub(crate) commitments: Option<Vec<OutputLabelsCommitment>>,
    }

    /// Evaluated garbled circuit data containing all wire labels
    #[derive(Debug, Clone)]
    pub struct Evaluated {
        pub(crate) input_labels: Vec<InputLabels<WireLabel>>,
        #[allow(dead_code)]
        pub(crate) labels: Vec<WireLabel>,
        pub(crate) encrypted_gates: Vec<EncryptedGate>,
        pub(crate) output_labels: Vec<OutputLabels<WireLabel>>,
        pub(crate) decoding: Option<Vec<OutputLabelsDecodingInfo>>,
        pub(crate) commitments: Option<Vec<OutputLabelsCommitment>>,
    }

    /// Evaluated garbled circuit that has been compressed to minimize memory footprint
    #[derive(Debug, Clone)]
    pub struct Compressed {
        pub(crate) input_labels: Vec<InputLabels<WireLabel>>,
        /// Input labels plus the encrypted gates is what constitutes a garbled circuit (GC).
        /// In scenarios where we expect the generator to prove their honest GC generation,
        /// even after performing the evaluation, we want the evaluator to keep the GC around
        /// in order to compare it against an honestly generated circuit. To reduce the memory
        /// footprint, we keep a hash digest of the encrypted gates.
        pub(crate) gates_digest: Vec<u8>,
        pub(crate) output_labels: Vec<OutputLabels<WireLabel>>,
        pub(crate) decoding: Option<Vec<OutputLabelsDecodingInfo>>,
        pub(crate) commitments: Option<Vec<OutputLabelsCommitment>>,
    }

    /// Evaluated garbled circuit output data
    #[derive(Debug)]
    pub struct Output {
        pub(crate) output_labels: Vec<OutputLabels<WireLabel>>,
        pub(crate) decoding: Option<Vec<OutputLabelsDecodingInfo>>,
    }

    impl State for Full {}
    impl State for Summary {}
    impl State for Partial {}
    impl State for Evaluated {}
    impl State for Compressed {}
    impl State for Output {}
}

use state::*;

/// Primary data structure for a garbled circuit with typed states found in [`state`]
#[derive(Debug, Clone)]
pub struct GarbledCircuit<S: State> {
    pub circ: Arc<Circuit>,
    pub(crate) state: S,
}

impl GarbledCircuit<Full> {
    /// Generate a garbled circuit with the provided input labels and delta.
    pub fn generate<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
        cipher: &C,
        circ: Arc<Circuit>,
        delta: Delta,
        input_labels: &[InputLabels<WireLabelPair>],
    ) -> Result<Self, Error> {
        let input_labels: Vec<WireLabelPair> = input_labels
            .iter()
            .map(|pair| pair.as_ref())
            .flatten()
            .copied()
            .collect();
        let (labels, encrypted_gates) = garble(cipher, &circ, delta, &input_labels)?;
        Ok(Self {
            circ,
            state: Full {
                labels,
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

    /// Returns input label pairs for each circuit input
    pub fn input_labels(&self) -> Vec<InputLabels<WireLabelPair>> {
        extract_input_labels(&self.circ, &self.state.labels)
            .expect("Garbled circuit labels should be valid")
    }

    /// Returns output label pairs for each circuit output
    pub fn output_labels(&self) -> Vec<OutputLabels<WireLabelPair>> {
        extract_output_labels(&self.circ, &self.state.labels)
            .expect("Garbled circuit labels should be valid")
    }

    /// Returns [`GarbledCircuit<Partial>`] which is safe to send an evaluator
    ///
    /// `reveal` flag determines whether the output decoding will be included
    /// `commit` flag determines whether commitments to the output labels will be included
    pub fn to_evaluator(
        &self,
        inputs: &[InputValue],
        reveal: bool,
        commit: bool,
    ) -> GarbledCircuit<Partial> {
        let input_labels: Vec<InputLabels<WireLabel>> = inputs
            .iter()
            .map(|value| {
                InputLabels::new(
                    value.input().clone(),
                    &WireLabelPair::choose(&self.state.labels, value.wires(), &value.wire_values()),
                )
                .expect("Circuit invariant violated, wrong wire count")
            })
            .collect();

        let constant_labels = self
            .circ
            .inputs()
            .iter()
            .filter_map(|input| {
                if input.value_type().is_constant() {
                    let value = match input.value_type() {
                        mpc_circuits::ValueType::ConstZero => false,
                        mpc_circuits::ValueType::ConstOne => true,
                        _ => panic!("value type should be constant"),
                    };
                    Some(
                        InputLabels::new(
                            input.clone(),
                            &WireLabelPair::choose(
                                &self.state.labels,
                                input.as_ref().wires(),
                                &[value],
                            ),
                        )
                        .expect("Circuit invariant violated, wrong wire count"),
                    )
                } else {
                    None
                }
            })
            .collect::<Vec<InputLabels<WireLabel>>>();

        GarbledCircuit {
            circ: self.circ.clone(),
            state: Partial {
                input_labels: [input_labels, constant_labels].concat(),
                encrypted_gates: self.state.encrypted_gates.clone(),
                decoding: reveal.then(|| self.decoding()),
                commitments: commit.then(|| self.output_commitments()),
            },
        }
    }

    /// Summarizes garbled circuit data to reduce memory footprint
    pub fn summarize(self) -> GarbledCircuit<Summary> {
        let input_labels = self.input_labels();
        let output_labels = self.output_labels();
        let decoding = self.decoding();

        GarbledCircuit {
            circ: self.circ,
            state: Summary {
                input_labels,
                output_labels,
                decoding,
            },
        }
    }
}

impl GarbledCircuit<Summary> {
    /// Returns all active inputs labels used to evaluate the circuit
    pub fn input_labels(&self) -> &[InputLabels<WireLabelPair>] {
        &self.state.input_labels
    }

    /// Returns all active output labels which are the result of circuit evaluation
    pub fn output_labels(&self) -> &[OutputLabels<WireLabelPair>] {
        &self.state.output_labels
    }

    /// Returns output label decoding info if available
    pub fn decoding(&self) -> &[OutputLabelsDecodingInfo] {
        &self.state.decoding
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
        input_labels: &[InputLabels<WireLabel>],
    ) -> Result<GarbledCircuit<Evaluated>, Error> {
        let sanitized_input_labels =
            SanitizedInputLabels::new(&self.circ, &self.state.input_labels, input_labels)?;
        let labels = evaluate(
            cipher,
            &self.circ,
            sanitized_input_labels,
            &self.state.encrypted_gates,
        )?;
        let output_labels = extract_output_labels(&self.circ, &labels)?;

        // Always check output labels against commitments if they're available
        if let Some(output_commitments) = self.state.commitments.as_ref() {
            output_commitments
                .iter()
                .zip(&output_labels)
                .map(|(commitment, labels)| commitment.validate(&labels))
                .collect::<Result<(), Error>>()?;
        }

        Ok(GarbledCircuit {
            circ: self.circ.clone(),
            state: Evaluated {
                input_labels: input_labels.to_vec(),
                labels,
                encrypted_gates: self.state.encrypted_gates,
                output_labels,
                decoding: self.state.decoding,
                commitments: self.state.commitments,
            },
        })
    }
}

impl GarbledCircuit<Evaluated> {
    /// Returns all active inputs labels used to evaluate the circuit
    pub fn input_labels(&self) -> &[InputLabels<WireLabel>] {
        &self.state.input_labels
    }

    /// Returns all active output labels which are the result of circuit evaluation
    pub fn output_labels(&self) -> &[OutputLabels<WireLabel>] {
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
    pub fn to_output(&self) -> GarbledCircuit<Output> {
        GarbledCircuit {
            circ: self.circ.clone(),
            state: Output {
                output_labels: self.output_labels().to_vec(),
                decoding: self.state.decoding.clone(),
            },
        }
    }

    /// Returns a compressed evaluated circuit to reduce memory utilization
    pub fn compress(self) -> GarbledCircuit<Compressed> {
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

    /// Returns decoded circuit outputs
    pub fn decode(&self) -> Result<Vec<OutputValue>, Error> {
        let decoding = self
            .state
            .decoding
            .as_ref()
            .ok_or(Error::InvalidLabelDecodingInfo)?;
        decode_output_labels(&self.circ, &self.state.output_labels, decoding)
    }
}

impl GarbledCircuit<Compressed> {
    /// Returns all active inputs labels used to evaluate the circuit
    pub fn input_labels(&self) -> &[InputLabels<WireLabel>] {
        &self.state.input_labels
    }

    /// Returns all active output labels which are the result of circuit evaluation
    pub fn output_labels(&self) -> &[OutputLabels<WireLabel>] {
        &self.state.output_labels
    }

    /// Returns whether or not output decoding info is available
    pub fn has_decoding(&self) -> bool {
        self.state.decoding.is_some()
    }

    /// Returns garbled circuit output
    pub fn to_output(&self) -> GarbledCircuit<Output> {
        GarbledCircuit {
            circ: self.circ.clone(),
            state: Output {
                output_labels: self.output_labels().to_vec(),
                decoding: self.state.decoding.clone(),
            },
        }
    }

    /// Returns decoded circuit outputs
    pub fn decode(&self) -> Result<Vec<OutputValue>, Error> {
        let decoding = self
            .state
            .decoding
            .as_ref()
            .ok_or(Error::InvalidLabelDecodingInfo)?;
        decode_output_labels(&self.circ, &self.state.output_labels, decoding)
    }
}

impl GarbledCircuit<Output> {
    /// Returns all output labels
    pub fn output_labels(&self) -> &[OutputLabels<WireLabel>] {
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
        let decoding = self
            .state
            .decoding
            .as_ref()
            .ok_or(Error::InvalidLabelDecodingInfo)?;
        decode_output_labels(&self.circ, &self.state.output_labels, decoding)
    }
}

pub fn validate_compressed_circuit<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
    cipher: &C,
    delta: Delta,
    input_labels: &[InputLabels<WireLabelPair>],
    gc: GarbledCircuit<Compressed>,
) -> Result<GarbledCircuit<Compressed>, Error> {
    validate_circuit(
        cipher,
        &gc.circ,
        delta,
        input_labels,
        None,
        Some(gc.state.gates_digest.clone()),
        gc.state.decoding.as_ref().map(Vec::as_slice),
        gc.state.commitments.as_ref().map(Vec::as_slice),
    )?;
    Ok(gc)
}

pub fn validate_evaluated_circuit<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
    cipher: &C,
    delta: Delta,
    input_labels: &[InputLabels<WireLabelPair>],
    gc: GarbledCircuit<Evaluated>,
) -> Result<GarbledCircuit<Evaluated>, Error> {
    validate_circuit(
        cipher,
        &gc.circ,
        delta,
        input_labels,
        Some(gc.state.encrypted_gates.as_slice()),
        None,
        gc.state.decoding.as_ref().map(Vec::as_slice),
        gc.state.commitments.as_ref().map(Vec::as_slice),
    )?;
    Ok(gc)
}

fn validate_circuit<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
    cipher: &C,
    circ: &Circuit,
    delta: Delta,
    input_labels: &[InputLabels<WireLabelPair>],
    encrypted_gates: Option<&[EncryptedGate]>,
    digest: Option<Vec<u8>>,
    output_decoding: Option<&[OutputLabelsDecodingInfo]>,
    output_commitments: Option<&[OutputLabelsCommitment]>,
) -> Result<(), Error> {
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

    let input_labels: Vec<WireLabelPair> = input_labels
        .iter()
        .map(|pair| pair.as_ref())
        .flatten()
        .copied()
        .collect();

    // Re-garble circuit using input labels.
    // We rely on the property of the "half-gates" garbling scheme that given the input
    // labels, the encrypted gates will always be computed deterministically.
    let (labels, encrypted_gates) = garble(cipher, circ, delta, &input_labels)?;

    // Compute the expected gates digest
    let expected_digest = gates_digest(&encrypted_gates);

    // If hashes don't match circuit wasn't garbled correctly
    if expected_digest != digest {
        return Err(Error::CorruptedGarbledCircuit);
    }

    // Check output decoding info if it was sent
    if let Some(output_decoding) = output_decoding {
        let expected_output_decoding = extract_output_labels(circ, &labels)?
            .iter()
            .map(|labels| labels.decoding())
            .collect::<Vec<_>>();

        if &expected_output_decoding != output_decoding {
            return Err(Error::CorruptedDecodingInfo);
        }
    }

    // Check output commitments if they were sent
    if let Some(output_commitments) = output_commitments {
        let expected_output_commitments = extract_output_labels(circ, &labels)?
            .iter()
            .map(|labels| labels.commit())
            .collect::<Vec<_>>();

        if &expected_output_commitments != output_commitments {
            return Err(Error::CorruptedGarbledCircuit);
        }
    }

    Ok(())
}

pub(crate) mod unchecked {
    use utils::iter::DuplicateCheckBy;

    use super::*;

    use crate::garble::label::unchecked::*;

    /// Partial garbled circuit which has not been validated against a circuit spec
    #[derive(Debug, Clone)]
    pub struct UncheckedGarbledCircuit {
        pub(crate) id: CircuitId,
        pub(crate) input_labels: Vec<UncheckedInputLabels>,
        pub(crate) encrypted_gates: Vec<Block>,
        pub(crate) decoding: Option<Vec<UncheckedOutputLabelsDecodingInfo>>,
        pub(crate) commitments: Option<Vec<UncheckedOutputLabelsCommitment>>,
    }

    #[cfg(test)]
    impl From<GarbledCircuit<Partial>> for UncheckedGarbledCircuit {
        fn from(gc: GarbledCircuit<Partial>) -> Self {
            Self {
                id: gc.circ.id().clone(),
                input_labels: gc
                    .state
                    .input_labels
                    .into_iter()
                    .map(UncheckedInputLabels::from)
                    .collect(),
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
                        .map(UncheckedOutputLabelsDecodingInfo::from)
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
            mut unchecked: UncheckedGarbledCircuit,
        ) -> Result<Self, Error> {
            // Validate circuit id
            if &unchecked.id != circ.id() {
                return Err(Error::ValidationError(format!(
                    "Wrong circuit id: expected {}, received {}",
                    circ.id().as_ref(),
                    unchecked.id.as_ref()
                )));
            }

            // Make sure the expected numbers of gates are present
            if unchecked.encrypted_gates.len() != 2 * circ.and_count() {
                return Err(Error::ValidationError(
                    "Incorrect number of encrypted gates".to_string(),
                ));
            }

            // Check for duplicate input ids
            if unchecked
                .input_labels
                .iter()
                .contains_dups_by(|input| &input.id)
            {
                return Err(Error::ValidationError("Duplicate inputs".to_string()));
            }

            // Make sure input labels are sorted by id
            unchecked.input_labels.sort_by_key(|labels| labels.id);

            // Collect set of input ids
            let input_ids = unchecked
                .input_labels
                .iter()
                .map(|input| input.id)
                .collect::<HashSet<_>>();

            // Check for unexpected input ids
            if !input_ids.iter().all(|id| circ.is_input_id(*id)) {
                return Err(Error::ValidationError("Invalid input id".to_string()));
            }

            // Convert input labels to checked type
            let input_labels = unchecked
                .input_labels
                .into_iter()
                .zip(
                    circ.inputs()
                        .iter()
                        .filter(|input| input_ids.contains(&input.id)),
                )
                .map(|(labels, input)| InputLabels::from_unchecked(input.clone(), labels))
                .collect::<Result<Vec<_>, _>>()?;

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
                            .collect::<Result<Vec<_>, Error>>()?,
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
                    input_labels,
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
        pub(crate) circ_id: CircuitId,
        pub(crate) output_labels: Vec<UncheckedOutputLabels>,
    }

    #[cfg(test)]
    impl From<GarbledCircuit<Output>> for UncheckedOutput {
        fn from(gc: GarbledCircuit<Output>) -> Self {
            Self {
                circ_id: gc.circ.id().clone(),
                output_labels: gc
                    .state
                    .output_labels
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
            full_output_labels: &[OutputLabels<WireLabelPair>],
        ) -> Result<Vec<OutputValue>, Error> {
            // Validate circuit id
            if &self.circ_id != circ.id() {
                return Err(Error::PeerError(format!(
                    "Received evaluated circuit with wrong id: expected {}, received {}",
                    circ.id().as_ref(),
                    self.circ_id.as_ref()
                )));
            }

            // Check for duplicates
            let output_ids: HashSet<usize> =
                self.output_labels.iter().map(|output| output.id).collect();

            if output_ids.len() != self.output_labels.len() {
                return Err(Error::PeerError(
                    "Received garbled circuit with duplicate outputs".to_string(),
                ));
            }

            // Make sure outputs are sorted
            self.output_labels
                .sort_by_key(|output_label| output_label.id);

            // Check all outputs were received
            if self.output_labels.len() != circ.output_count() {
                return Err(Error::InvalidOutputLabels);
            }

            let output_labels = self
                .output_labels
                .into_iter()
                .zip(circ.outputs())
                .map(|(labels, output)| OutputLabels::from_unchecked(output.clone(), labels))
                .collect::<Result<Vec<_>, _>>()?;

            // Validates that each output label is authentic then decodes them
            full_output_labels
                .iter()
                .zip(&output_labels)
                .map(|(full, ev)| {
                    full.validate(ev)?;
                    ev.decode(&full.decoding())
                })
                .collect::<Result<Vec<_>, Error>>()
        }
    }
}

#[cfg(test)]
mod tests {
    use aes::{Aes128, NewBlockCipher};
    use mpc_circuits::AES_128_REVERSE;
    use rand_chacha::ChaCha12Rng;
    use rand_core::SeedableRng;

    use super::*;

    #[test]
    fn test_uninitialized_label() {
        let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
        let mut rng = ChaCha12Rng::seed_from_u64(0);
        let circ = Arc::new(Circuit::load_bytes(AES_128_REVERSE).unwrap());

        let (input_labels, delta) = InputLabels::generate(&mut rng, &circ, None);

        let err = GarbledCircuit::generate(&cipher, circ, delta, &input_labels[1..]).unwrap_err();

        assert!(matches!(err, Error::UninitializedLabel(_)));
    }

    #[test]
    fn test_circuit_validation_pass() {
        let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
        let mut rng = ChaCha12Rng::seed_from_u64(0);
        let circ = Arc::new(Circuit::load_bytes(AES_128_REVERSE).unwrap());

        let key = circ.input(0).unwrap().to_value(vec![0u8; 16]).unwrap();
        let msg = circ.input(1).unwrap().to_value(vec![0u8; 16]).unwrap();
        let (input_labels, delta) = InputLabels::generate(&mut rng, &circ, None);

        let gc = GarbledCircuit::generate(&cipher, circ.clone(), delta, &input_labels).unwrap();

        let key_labels = input_labels[0].select(&key).unwrap();
        let msg_labels = input_labels[1].select(&msg).unwrap();

        let partial_gc = gc.to_evaluator(&[], true, false);
        let ev_gc = partial_gc
            .evaluate(&cipher, &[key_labels, msg_labels])
            .unwrap();

        let ev_gc = validate_evaluated_circuit(&cipher, delta, &input_labels, ev_gc).unwrap();

        let cmp_gc = ev_gc.compress();

        validate_compressed_circuit(&cipher, delta, &input_labels, cmp_gc).unwrap();
    }

    #[test]
    fn test_circuit_validation_fail_bad_gate() {
        let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
        let mut rng = ChaCha12Rng::seed_from_u64(0);
        let circ = Arc::new(Circuit::load_bytes(AES_128_REVERSE).unwrap());

        let key = circ.input(0).unwrap().to_value(vec![0u8; 16]).unwrap();
        let msg = circ.input(1).unwrap().to_value(vec![0u8; 16]).unwrap();
        let (input_labels, delta) = InputLabels::generate(&mut rng, &circ, None);

        let mut gc = GarbledCircuit::generate(&cipher, circ.clone(), delta, &input_labels).unwrap();

        // set bogus gate
        gc.state.encrypted_gates[0].0[0] = Block::new(0);

        let key_labels = input_labels[0].select(&key).unwrap();
        let msg_labels = input_labels[1].select(&msg).unwrap();

        let partial_gc = gc.to_evaluator(&[], true, false);
        let ev_gc = partial_gc
            .evaluate(&cipher, &[key_labels, msg_labels])
            .unwrap();

        let err =
            validate_evaluated_circuit(&cipher, delta, &input_labels, ev_gc.clone()).unwrap_err();

        assert!(matches!(err, Error::CorruptedGarbledCircuit));

        let cmp_gc = ev_gc.compress();

        let err = validate_compressed_circuit(&cipher, delta, &input_labels, cmp_gc).unwrap_err();

        assert!(matches!(err, Error::CorruptedGarbledCircuit));
    }

    #[test]
    fn test_circuit_validation_fail_bad_input_label() {
        let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
        let mut rng = ChaCha12Rng::seed_from_u64(0);
        let circ = Arc::new(Circuit::load_bytes(AES_128_REVERSE).unwrap());

        let key = circ.input(0).unwrap().to_value(vec![0u8; 16]).unwrap();
        let msg = circ.input(1).unwrap().to_value(vec![0u8; 16]).unwrap();
        let (mut input_labels, delta) = InputLabels::generate(&mut rng, &circ, None);

        let gc = GarbledCircuit::generate(&cipher, circ.clone(), delta, &input_labels).unwrap();

        // set bogus label
        input_labels[0].set_label(0, WireLabelPair::new(0, Block::new(0), Block::new(0)));

        let key_labels = input_labels[0].select(&key).unwrap();
        let msg_labels = input_labels[1].select(&msg).unwrap();

        let partial_gc = gc.to_evaluator(&[], true, false);
        let ev_gc = partial_gc
            .evaluate(&cipher, &[key_labels, msg_labels])
            .unwrap();

        let err =
            validate_evaluated_circuit(&cipher, delta, &input_labels, ev_gc.clone()).unwrap_err();

        assert!(matches!(err, Error::CorruptedGarbledCircuit));

        let cmp_gc = ev_gc.compress();

        let err = validate_compressed_circuit(&cipher, delta, &input_labels, cmp_gc).unwrap_err();

        assert!(matches!(err, Error::CorruptedGarbledCircuit));
    }

    #[test]
    /// The Generator sends invalid output label decoding info which causes the evaluator to
    /// derive incorrect output. Testing that this will be detected during validation.
    fn test_circuit_validation_fail_bad_output_decoding() {
        let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
        let mut rng = ChaCha12Rng::seed_from_u64(0);
        let circ = Arc::new(Circuit::load_bytes(AES_128_REVERSE).unwrap());

        let key = circ.input(0).unwrap().to_value(vec![0u8; 16]).unwrap();
        let msg = circ.input(1).unwrap().to_value(vec![0u8; 16]).unwrap();
        let (input_labels, delta) = InputLabels::generate(&mut rng, &circ, None);

        let mut gc = GarbledCircuit::generate(&cipher, circ.clone(), delta, &input_labels).unwrap();

        // Flip the last two output labels. This will cause the generator to compute the
        // corrupted decoding info.
        let last_pair = gc.state.labels.pop().unwrap();
        let last_pair_flipped =
            WireLabelPair::new(last_pair.id(), *last_pair.high(), *last_pair.low());
        gc.state.labels.push(last_pair_flipped);

        let key_labels = input_labels[0].select(&key).unwrap();
        let msg_labels = input_labels[1].select(&msg).unwrap();

        let partial_gc = gc.to_evaluator(&[], true, true);

        let ev_gc = partial_gc
            .evaluate(&cipher, &[key_labels, msg_labels])
            .unwrap();

        let err =
            validate_evaluated_circuit(&cipher, delta, &input_labels, ev_gc.clone()).unwrap_err();

        assert!(matches!(err, Error::CorruptedDecodingInfo));

        let cmp_gc = ev_gc.compress();

        let err = validate_compressed_circuit(&cipher, delta, &input_labels, cmp_gc).unwrap_err();

        assert!(matches!(err, Error::CorruptedDecodingInfo));
    }

    #[test]
    fn test_circuit_validation_fail_bad_output_commitment() {
        let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
        let mut rng = ChaCha12Rng::seed_from_u64(0);
        let circ = Arc::new(Circuit::load_bytes(AES_128_REVERSE).unwrap());

        let key = circ.input(0).unwrap().to_value(vec![0u8; 16]).unwrap();
        let msg = circ.input(1).unwrap().to_value(vec![0u8; 16]).unwrap();
        let (mut input_labels, delta) = InputLabels::generate(&mut rng, &circ, None);

        let gc = GarbledCircuit::generate(&cipher, circ.clone(), delta, &input_labels).unwrap();

        // set bogus high label (the opposite label the evaluator receives)
        // evaluation should pass but the circuit validation should fail because the commitment is bad
        let low_label = input_labels[0].get_label(0).low().clone();
        input_labels[0].set_label(0, WireLabelPair::new(0, low_label, Block::new(0)));

        let key_labels = input_labels[0].select(&key).unwrap();
        let msg_labels = input_labels[1].select(&msg).unwrap();

        let partial_gc = gc.to_evaluator(&[], true, true);
        let ev_gc = partial_gc
            .evaluate(&cipher, &[key_labels, msg_labels])
            .unwrap();

        let err =
            validate_evaluated_circuit(&cipher, delta, &input_labels, ev_gc.clone()).unwrap_err();

        assert!(matches!(err, Error::CorruptedGarbledCircuit));

        let cmp_gc = ev_gc.compress();

        let err = validate_compressed_circuit(&cipher, delta, &input_labels, cmp_gc).unwrap_err();

        assert!(matches!(err, Error::CorruptedGarbledCircuit));
    }
}
