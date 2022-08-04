use rand::{CryptoRng, Rng};
use std::sync::Arc;

use crate::{
    block::Block,
    garble::{Error, InputError},
    msgs::garble as msgs,
};
use mpc_circuits::{Circuit, Input, Output};

/// We call the wire labels "binary" to emphasize that acc.to Free-XOR,
/// W₀ XOR Δ, = W₁. Later in the zk label decoding protocol we will convert
/// Δ into an "arithmetic" one, so that W₀ + Δ, = W₁.
pub type BinaryLabel = WireLabel<Block>;

/// Wire label of a garbled circuit
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WireLabel<T: Copy> {
    /// Wire id
    pub id: usize,
    /// Wire label which corresponds to the logical level of a circuit wire
    value: T,
}

impl<T: Copy> AsRef<T> for WireLabel<T> {
    fn as_ref(&self) -> &T {
        &self.value
    }
}

impl WireLabel<Block> {
    pub fn new(id: usize, value: Block) -> Self {
        Self { id, value }
    }

    pub fn random<R: Rng + CryptoRng>(id: usize, rng: &mut R) -> Self {
        Self {
            id,
            value: Block::random(rng),
        }
    }
}

#[derive(Debug, Clone)]
pub struct InputValue {
    input: Input,
    value: Vec<bool>,
}

impl InputValue {
    pub fn new(input: Input, value: &[bool]) -> Self {
        assert!(input.group().len() == value.len());
        Self {
            input,
            value: value.to_vec(),
        }
    }

    pub fn value(&self) -> &[bool] {
        &self.value
    }

    pub fn len(&self) -> usize {
        self.input.group().len()
    }

    pub fn wires(&self) -> &[usize] {
        self.input.group().wires()
    }
}

#[derive(Debug, Clone)]
pub struct OutputValue {
    output: Output,
    value: Vec<bool>,
}

impl AsRef<[bool]> for OutputValue {
    fn as_ref(&self) -> &[bool] {
        &self.value
    }
}

impl OutputValue {
    pub fn new(output: Output, value: &[bool]) -> Self {
        assert!(output.group().len() == value.len());
        Self {
            output,
            value: value.to_vec(),
        }
    }

    pub fn value(&self) -> &[bool] {
        &self.value
    }

    pub fn len(&self) -> usize {
        self.output.group().len()
    }

    pub fn wires(&self) -> &[usize] {
        self.output.group().wires()
    }
}

#[derive(Debug, Clone)]
pub struct EncryptedGate([Block; 2]);

impl EncryptedGate {
    pub(crate) fn new(inner: [Block; 2]) -> Self {
        Self(inner)
    }

    pub(crate) fn inner(&self) -> &[Block; 2] {
        &self.0
    }
}

/// Complete half-gate garbled circuit data, including delta which can be used to
/// derive the private inputs of the Garbler
pub struct FullGarbledCircuit {
    pub circ: Arc<Circuit>,
    pub wire_labels: Vec<[BinaryLabel; 2]>,
    pub encrypted_gates: Vec<EncryptedGate>,
    pub delta: Block,
}

pub struct GarbledCircuit {
    pub circ: Arc<Circuit>,
    pub input_labels: Vec<BinaryLabel>,
    pub encrypted_gates: Vec<EncryptedGate>,
    pub decoding: Option<Vec<bool>>,
}

pub struct EvaluatedGarbledCircuit {
    pub circ: Arc<Circuit>,
    pub output_labels: Vec<BinaryLabel>,
    pub output: Option<Vec<bool>>,
}

impl GarbledCircuit {
    pub fn from_msg(circ: Arc<Circuit>, msg: msgs::GarbledCircuit) -> Result<Self, Error> {
        if msg.id != *circ.id() {
            return Err(Error::PeerError(format!(
                "Received garbled circuit with wrong id: expected {}, received {}",
                circ.id().as_ref().to_string(),
                msg.id.as_ref().to_string()
            )));
        }

        Ok(GarbledCircuit {
            circ,
            input_labels: msg.input_labels,
            encrypted_gates: msg.encrypted_gates,
            decoding: msg.decoding,
        })
    }
}

impl FullGarbledCircuit {
    /// Returns output label decoding
    pub fn decoding(&self) -> Vec<bool> {
        self.wire_labels
            .iter()
            .skip(self.circ.len() - self.circ.output_len())
            .map(|labels| labels[0].as_ref().lsb() == 1)
            .collect()
    }

    /// Returns full set of output labels
    pub fn output_labels(&self) -> &[[BinaryLabel; 2]] {
        &self.wire_labels[self.circ.len() - self.circ.output_len()..]
    }

    /// Returns `GarbledCircuit` which is safe to send an evaluator
    pub fn to_evaluator(&self, inputs: &[InputValue], decoding: bool) -> GarbledCircuit {
        let input_labels: Vec<BinaryLabel> = inputs
            .iter()
            .map(|input| choose_labels(&self.wire_labels, input.wires(), input.value()))
            .flatten()
            .collect();

        GarbledCircuit {
            circ: self.circ.clone(),
            input_labels: input_labels,
            encrypted_gates: self.encrypted_gates.clone(),
            decoding: decoding.then(|| self.decoding()),
        }
    }

    /// Validates that provided output labels are correct
    pub fn validate_output(&self, output_labels: &[BinaryLabel]) -> Result<(), Error> {
        if output_labels.len() != self.circ.output_count() {
            return Err(Error::InvalidOutputLabels);
        }
        let pairs = self
            .wire_labels
            .iter()
            .enumerate()
            .skip(self.circ.len() - self.circ.output_len());

        if output_labels.iter().zip(pairs).all(|(label, (id, pair))| {
            (label.id == id)
                & ((label.value == *pair[0].as_ref()) | (label.value == *pair[1].as_ref()))
        }) {
            Ok(())
        } else {
            Err(Error::InvalidOutputLabels)
        }
    }
}

/// Generates pairs of wire labels \[W_0, W_0 ^ delta\]
pub fn generate_labels<R: Rng + CryptoRng>(
    rng: &mut R,
    delta: Option<&Block>,
    count: usize,
    offset: usize,
) -> (Vec<[BinaryLabel; 2]>, Block) {
    let delta = match delta {
        Some(delta) => *delta,
        None => {
            let mut delta = Block::random(rng);
            delta.set_lsb();
            delta
        }
    };
    let low = Block::random_vec(rng, count);
    (
        low.into_iter()
            .enumerate()
            .map(|(id, value)| {
                [
                    BinaryLabel {
                        id: id + offset,
                        value,
                    },
                    BinaryLabel {
                        id: id + offset,
                        value: value ^ delta,
                    },
                ]
            })
            .collect(),
        delta,
    )
}

/// Returns wire labels corresponding to wire truth values
///
/// Panics if wire is not in label collection
pub fn choose_labels<T: Copy>(labels: &[[T; 2]], wires: &[usize], values: &[bool]) -> Vec<T> {
    wires
        .iter()
        .zip(values.iter())
        .map(|(id, value)| labels[*id][*value as usize])
        .collect()
}

/// Clones an array of input labels, sorts them, and validates according to a circuit description.
pub fn prepare_inputs(circ: &Circuit, inputs: &[BinaryLabel]) -> Result<Vec<BinaryLabel>, Error> {
    let mut inputs = Vec::from(inputs);
    if circ.input_len() != inputs.len() {
        return Err(Error::InvalidInput(InputError::InvalidCount(
            circ.input_len(),
            inputs.len(),
        )));
    }

    inputs.sort_by_key(|label| label.id);
    inputs.dedup_by_key(|label| label.id);

    if circ.input_len() != inputs.len() {
        return Err(Error::InvalidInput(InputError::Duplicate));
    }

    Ok(inputs)
}

/// Decodes output wire labels into plaintext.
///
/// Thanks to the point-and-permute (p&p) technique, the two adjacent labels
/// will have the opposite p&p bits. We apply the decoding to the p&p bits.
pub fn decode(labels: &[BinaryLabel], decoding: &[bool]) -> Vec<bool> {
    assert!(
        labels.len() == decoding.len(),
        "arrays are different length"
    );
    labels
        .iter()
        .zip(decoding)
        .map(|(label, decode)| (label.as_ref().lsb() == 1) ^ decode)
        .collect()
}
