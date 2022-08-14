use cipher::{consts::U16, BlockCipher, BlockEncrypt};
use std::sync::Arc;

use crate::{
    block::Block,
    garble::{
        evaluator::evaluate, generator::garble, Delta, Error, InputLabels, SanitizedInputLabels,
        WireLabel, WireLabelPair,
    },
};
use mpc_circuits::{Circuit, InputValue, OutputValue};

use super::label::{OutputLabels, OutputLabelsEncoding};

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
            labels,
            encrypted_gates,
            delta,
        })
    }

    /// Returns output label encodings
    fn encoding(&self) -> Vec<OutputLabelsEncoding> {
        self.output_labels()
            .iter()
            .map(|labels| labels.encode())
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
    pub fn to_evaluator(&self, inputs: &[InputValue], encoding: bool) -> GarbledCircuit {
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
            encoding: encoding.then(|| self.encoding()),
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

/// A garbled circuit including input labels from the generator and (optionally) the encoding
/// to reveal the plaintext output of the circuit.
pub struct GarbledCircuit {
    pub circ: Arc<Circuit>,
    pub(crate) input_labels: Vec<InputLabels<WireLabel>>,
    pub(crate) encrypted_gates: Vec<EncryptedGate>,
    pub(crate) encoding: Option<Vec<OutputLabelsEncoding>>,
}

impl GarbledCircuit {
    /// Returns whether or not output encoding was provided
    pub fn has_encoding(&self) -> bool {
        self.encoding.is_some()
    }

    /// Evaluates a garbled circuit using provided input labels. These labels are combined with labels sent by the generator
    /// and checked for correctness using the circuit spec.
    pub fn evaluate<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
        &self,
        cipher: &C,
        input_labels: &[InputLabels<WireLabel>],
    ) -> Result<EvaluatedGarbledCircuit, Error> {
        let input_labels = SanitizedInputLabels::new(&self.circ, &self.input_labels, input_labels)?;
        let labels = evaluate(cipher, &self.circ, input_labels, &self.encrypted_gates)?;

        Ok(EvaluatedGarbledCircuit::new(
            self.circ.clone(),
            labels,
            self.encoding.clone(),
        ))
    }
}

/// A garbled circuit which has been evaluated
pub struct EvaluatedGarbledCircuit {
    pub circ: Arc<Circuit>,
    labels: Vec<WireLabel>,
    encoding: Option<Vec<OutputLabelsEncoding>>,
}

impl EvaluatedGarbledCircuit {
    /// Creates new evaluated circuit
    fn new(
        circ: Arc<Circuit>,
        labels: Vec<WireLabel>,
        encoding: Option<Vec<OutputLabelsEncoding>>,
    ) -> Self {
        Self {
            circ,
            labels,
            encoding,
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

    /// Returns whether or not output encoding was provided
    pub fn has_encoding(&self) -> bool {
        self.encoding.is_some()
    }

    /// Returns decoded circuit outputs
    pub fn decode(&self) -> Result<Vec<OutputValue>, Error> {
        let encoding = match &self.encoding {
            Some(encoding) => encoding,
            None => return Err(Error::InvalidLabelEncoding),
        };
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

        let result = FullGarbledCircuit::generate(&cipher, circ, delta, &input_labels[1..]);
        assert!(matches!(result, Err(Error::UninitializedLabel(_))));
    }
}
