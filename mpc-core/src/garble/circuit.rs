use cipher::{consts::U16, BlockCipher, BlockEncrypt};
use std::sync::Arc;

use crate::{
    block::Block,
    garble::{
        evaluator::evaluate, generator::garble, label::SanitizedInputLabels, Delta, Error,
        InputLabels, WireLabel, WireLabelPair,
    },
};
use mpc_circuits::{Circuit, InputValue, OutputValue};

use super::label::{OutputLabels, OutputLabelsCommitment, OutputLabelsEncoding};

#[derive(Debug, Clone)]
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

pub trait Data {}

/// Full garbled circuit data. This includes all wire label pairs, encrypted gates and delta.
#[derive(Debug)]
pub struct Full {
    labels: Vec<WireLabelPair>,
    encrypted_gates: Vec<EncryptedGate>,
    #[allow(dead_code)]
    delta: Delta,
}

/// Garbled circuit data including input labels from the generator and (optionally) the output encoding
/// to reveal the plaintext output of the circuit.
#[derive(Debug)]
pub struct Partial {
    pub(crate) input_labels: Vec<InputLabels<WireLabel>>,
    pub(crate) encrypted_gates: Vec<EncryptedGate>,
    pub(crate) encoding: Option<Vec<OutputLabelsEncoding>>,
    pub(crate) commitments: Option<Vec<OutputLabelsCommitment>>,
}

/// Evaluated garbled circuit data containing all wire labels
#[derive(Debug, Clone)]
pub struct Evaluated {
    labels: Vec<WireLabel>,
    encoding: Option<Vec<OutputLabelsEncoding>>,
}

/// Evaluated garbled circuit output data
#[derive(Debug)]
pub struct Output {
    pub(crate) labels: Vec<OutputLabels<WireLabel>>,
    pub(crate) encoding: Option<Vec<OutputLabelsEncoding>>,
}

impl Data for Full {}
impl Data for Partial {}
impl Data for Evaluated {}
impl Data for Output {}

#[derive(Debug, Clone)]
pub struct GarbledCircuit<D: Data> {
    pub circ: Arc<Circuit>,
    pub(crate) data: D,
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
            data: Full {
                labels,
                encrypted_gates,
                delta,
            },
        })
    }

    /// Returns output label encodings
    pub(crate) fn encoding(&self) -> Vec<OutputLabelsEncoding> {
        self.output_labels()
            .iter()
            .map(|labels| labels.encode())
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

    /// Returns output label pairs for each circuit output
    pub fn output_labels(&self) -> Vec<OutputLabels<WireLabelPair>> {
        self.circ
            .outputs()
            .iter()
            .map(|output| {
                OutputLabels::new(
                    output.clone(),
                    &output
                        .as_ref()
                        .wires()
                        .iter()
                        .map(|wire_id| self.data.labels[*wire_id])
                        .collect::<Vec<WireLabelPair>>(),
                )
            })
            .collect::<Result<Vec<OutputLabels<WireLabelPair>>, Error>>()
            .expect("Garbled circuit output labels should be valid")
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
                    &WireLabelPair::choose(&self.data.labels, value.wires(), &value.wire_values()),
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
                                &self.data.labels,
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
            data: Partial {
                input_labels: [input_labels, constant_labels].concat(),
                encrypted_gates: self.data.encrypted_gates.clone(),
                encoding: reveal.then(|| self.encoding()),
                commitments: commit.then(|| self.output_commitments()),
            },
        }
    }

    /// Validates that provided output labels are correct
    pub fn validate_output(&self, output_labels: &[WireLabel]) -> Result<(), Error> {
        if output_labels.len() != self.circ.output_count() {
            return Err(Error::InvalidOutputLabels);
        }
        let pairs = self
            .data
            .labels
            .iter()
            .enumerate()
            .skip(self.circ.len() - self.circ.output_len());

        if output_labels.iter().zip(pairs).all(|(label, (id, pair))| {
            (label.id() == id)
                & ((*label.as_ref() == *pair.low()) | (*label.as_ref() == *pair.high()))
        }) {
            Ok(())
        } else {
            Err(Error::InvalidOutputLabels)
        }
    }
}

impl GarbledCircuit<Partial> {
    /// Returns whether or not output encoding is available
    pub fn has_encoding(&self) -> bool {
        self.data.encoding.is_some()
    }

    /// Returns output commitments
    pub fn output_commitments(&self) -> Option<&Vec<OutputLabelsCommitment>> {
        self.data.commitments.as_ref()
    }

    /// Evaluates a garbled circuit using provided input labels. These labels are combined with labels sent by the generator
    /// and checked for correctness using the circuit spec.
    pub fn evaluate<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
        &self,
        cipher: &C,
        input_labels: &[InputLabels<WireLabel>],
    ) -> Result<GarbledCircuit<Evaluated>, Error> {
        let input_labels =
            SanitizedInputLabels::new(&self.circ, &self.data.input_labels, input_labels)?;
        let labels = evaluate(cipher, &self.circ, input_labels, &self.data.encrypted_gates)?;

        Ok(GarbledCircuit {
            circ: self.circ.clone(),
            data: Evaluated {
                labels,
                encoding: self.data.encoding.clone(),
            },
        })
    }
}

impl GarbledCircuit<Evaluated> {
    /// Returns all active output labels which are the result of circuit evaluation
    pub fn output_labels(&self) -> Vec<OutputLabels<WireLabel>> {
        self.circ
            .outputs()
            .iter()
            .map(|output| {
                OutputLabels::new(
                    output.clone(),
                    &output
                        .as_ref()
                        .wires()
                        .iter()
                        .map(|wire_id| self.data.labels[*wire_id])
                        .collect::<Vec<WireLabel>>(),
                )
            })
            .collect::<Result<Vec<OutputLabels<WireLabel>>, Error>>()
            .expect("Evaluated circuit output labels should be valid")
    }

    /// Returns whether or not output encoding is available
    pub fn has_encoding(&self) -> bool {
        self.data.encoding.is_some()
    }

    pub fn to_output(&self) -> GarbledCircuit<Output> {
        GarbledCircuit {
            circ: self.circ.clone(),
            data: Output {
                labels: self.output_labels(),
                encoding: self.data.encoding.clone(),
            },
        }
    }

    /// Returns decoded circuit outputs
    pub fn decode(&self) -> Result<Vec<OutputValue>, Error> {
        let encoding = self
            .data
            .encoding
            .as_ref()
            .ok_or(Error::InvalidLabelEncoding)?;
        if encoding.len() != self.circ.output_count() {
            return Err(Error::InvalidLabelEncoding);
        }
        let mut outputs: Vec<OutputValue> = Vec::with_capacity(self.circ.output_count());
        for (labels, encoding) in self.output_labels().iter().zip(encoding) {
            outputs.push(labels.decode(encoding)?);
        }
        Ok(outputs)
    }
}

impl GarbledCircuit<Output> {
    /// Returns all output labels
    pub fn output_labels(&self) -> &[OutputLabels<WireLabel>] {
        &self.data.labels
    }

    /// Returns whether or not output encoding is available
    pub fn has_encoding(&self) -> bool {
        self.data.encoding.is_some()
    }

    /// Returns output label encoding if available
    pub fn encoding(&self) -> Option<Vec<OutputLabelsEncoding>> {
        self.data.encoding.clone()
    }

    /// Returns decoded circuit outputs
    pub fn decode(&self) -> Result<Vec<OutputValue>, Error> {
        let encoding = self
            .data
            .encoding
            .as_ref()
            .ok_or(Error::InvalidLabelEncoding)?;
        if encoding.len() != self.circ.output_count() {
            return Err(Error::InvalidLabelEncoding);
        }
        let mut outputs: Vec<OutputValue> = Vec::with_capacity(self.circ.output_count());
        for (labels, encoding) in self.output_labels().iter().zip(encoding) {
            outputs.push(labels.decode(encoding)?);
        }
        Ok(outputs)
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
        let mut rng = ChaCha12Rng::from_entropy();
        let circ = Arc::new(Circuit::load_bytes(AES_128_REVERSE).unwrap());

        let (input_labels, delta) = InputLabels::generate(&mut rng, &circ, None);

        let result = GarbledCircuit::generate(&cipher, circ, delta, &input_labels[1..]);
        assert!(matches!(result, Err(Error::UninitializedLabel(_))));
    }
}
