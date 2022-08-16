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

pub trait Data {}

/// Full garbled circuit data. This includes all wire label pairs, encrypted gates and delta.
pub struct Full {
    labels: Vec<WireLabelPair>,
    encrypted_gates: Vec<EncryptedGate>,
    #[allow(dead_code)]
    delta: Delta,
}

/// Garbled circuit data including input labels from the generator and (optionally) the output encoding
/// to reveal the plaintext output of the circuit.
pub struct Partial {
    pub(crate) input_labels: Vec<InputLabels<WireLabel>>,
    pub(crate) encrypted_gates: Vec<EncryptedGate>,
    pub(crate) encoding: Option<Vec<OutputLabelsEncoding>>,
}

/// Evaluated garbled circuit data, which can be used to determine the plaintext circuit output if
/// the generator sent the output label encoding.
pub struct Evaluated {
    labels: Vec<WireLabel>,
    encoding: Option<Vec<OutputLabelsEncoding>>,
}

impl Data for Full {}
impl Data for Partial {}
impl Data for Evaluated {}

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
                        .map(|wire_id| self.data.labels[*wire_id])
                        .collect::<Vec<WireLabelPair>>(),
                )
            })
            .collect()
    }

    /// Returns [`GarbledCircuit<Partial>`] which is safe to send an evaluator
    pub fn to_evaluator(&self, inputs: &[InputValue], encoding: bool) -> GarbledCircuit<Partial> {
        let input_labels: Vec<InputLabels<WireLabel>> = inputs
            .iter()
            .map(|value| {
                InputLabels::new(
                    value.input().clone(),
                    &WireLabelPair::choose(&self.data.labels, value.wires(), value.as_ref()),
                )
            })
            .collect();

        GarbledCircuit {
            circ: self.circ.clone(),
            data: Partial {
                input_labels,
                encrypted_gates: self.data.encrypted_gates.clone(),
                encoding: encoding.then(|| self.encoding()),
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
    /// Returns whether or not output encoding was provided
    pub fn has_encoding(&self) -> bool {
        self.data.encoding.is_some()
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
                        .map(|wire_id| self.data.labels[*wire_id])
                        .collect::<Vec<WireLabel>>(),
                )
            })
            .collect()
    }

    /// Returns whether or not output encoding was provided
    pub fn has_encoding(&self) -> bool {
        self.data.encoding.is_some()
    }

    /// Returns decoded circuit outputs
    pub fn decode(&self) -> Result<Vec<OutputValue>, Error> {
        let encoding = match &self.data.encoding {
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

        let result = GarbledCircuit::generate(&cipher, circ, delta, &input_labels[1..]);
        assert!(matches!(result, Err(Error::UninitializedLabel(_))));
    }
}
