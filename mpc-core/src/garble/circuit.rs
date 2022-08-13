use std::sync::Arc;

use crate::{
    block::Block,
    garble::{label::decode, Delta, Error, InputLabels, WireLabel, WireLabelPair},
};
use mpc_circuits::{Circuit, InputValue, OutputValue};

use super::label::OutputLabels;

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

/// Complete half-gate garbled circuit data, including delta which can be used to
/// derive the private inputs of the Garbler
pub struct FullGarbledCircuit {
    pub circ: Arc<Circuit>,
    labels: Vec<WireLabelPair>,
    encrypted_gates: Vec<EncryptedGate>,
    delta: Delta,
}

impl FullGarbledCircuit {
    pub(crate) fn new(
        circ: Arc<Circuit>,
        labels: Vec<WireLabelPair>,
        encrypted_gates: Vec<EncryptedGate>,
        delta: Delta,
    ) -> Self {
        Self {
            circ,
            labels,
            encrypted_gates,
            delta,
        }
    }

    /// Returns output label decoding
    pub fn decoding(&self) -> Vec<bool> {
        self.labels
            .iter()
            .skip(self.circ.len() - self.circ.output_len())
            .map(|labels| labels.low().lsb() == 1)
            .collect()
    }

    /// Returns all output labels
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
                        .map(|wire_id| self.labels[*wire_id])
                        .collect::<Vec<WireLabelPair>>(),
                )
            })
            .collect()
    }

    /// Returns [`GarbledCircuit`] which is safe to send an evaluator
    pub fn to_evaluator(&self, inputs: &[InputValue], decoding: bool) -> GarbledCircuit {
        let input_labels: Vec<InputLabels<WireLabel>> = inputs
            .iter()
            .map(|value| {
                InputLabels::new(
                    value.input().clone(),
                    &WireLabelPair::choose(&self.labels, value.wires(), value.as_ref()),
                )
            })
            .collect();

        GarbledCircuit {
            circ: self.circ.clone(),
            input_labels: input_labels,
            encrypted_gates: self.encrypted_gates.clone(),
            decoding: decoding.then(|| self.decoding()),
        }
    }

    /// Validates that provided output labels are correct
    pub fn validate_output(&self, output_labels: &[WireLabel]) -> Result<(), Error> {
        if output_labels.len() != self.circ.output_count() {
            return Err(Error::InvalidOutputLabels);
        }
        let pairs = self
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

/// A garbled circuit including input labels from the generator and (optionally) the decoding
/// to reveal the plaintext output of the circuit.
pub struct GarbledCircuit {
    pub circ: Arc<Circuit>,
    pub(crate) input_labels: Vec<InputLabels<WireLabel>>,
    pub(crate) encrypted_gates: Vec<EncryptedGate>,
    pub(crate) decoding: Option<Vec<bool>>,
}

/// A garbled circuit which has been evaluated
pub struct EvaluatedGarbledCircuit {
    pub circ: Arc<Circuit>,
    labels: Vec<WireLabel>,
    decoding: Option<Vec<bool>>,
}

impl EvaluatedGarbledCircuit {
    /// Creates new evaluated circuit
    pub(crate) fn new(
        circ: Arc<Circuit>,
        labels: Vec<WireLabel>,
        decoding: Option<Vec<bool>>,
    ) -> Self {
        Self {
            circ,
            labels,
            decoding,
        }
    }

    /// Returns all output labels
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
                        .map(|wire_id| self.labels[*wire_id])
                        .collect::<Vec<WireLabel>>(),
                )
            })
            .collect()
    }

    pub fn decode(&self) -> Result<Vec<OutputValue>, Error> {
        let decoding = match &self.decoding {
            Some(decoding) => decoding,
            None => return Err(Error::InvalidLabelDecoding),
        };
        if decoding.len() != self.circ.output_len() {
            return Err(Error::InvalidLabelDecoding);
        }
        let mut outputs: Vec<OutputValue> = Vec::with_capacity(self.circ.output_count());
        let id_offset = self.circ.len() - self.circ.output_len();
        for output in self.circ.outputs() {
            outputs.push(OutputValue::new(
                output.clone(),
                &output
                    .as_ref()
                    .wires()
                    .iter()
                    .map(|wire_id| {
                        // This should never panic due to invariants upheld by `Circuit`
                        decode(&self.labels[*wire_id], decoding[*wire_id - id_offset])
                    })
                    .collect::<Vec<bool>>(),
            )?)
        }
        Ok(outputs)
    }
}
