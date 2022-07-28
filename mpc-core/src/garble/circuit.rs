use rand::{CryptoRng, Rng};
use std::sync::Arc;

use crate::block::Block;
use crate::garble::{Error, InputError};
use mpc_circuits::Circuit;

pub type BinaryLabel = WireLabel<Block>;

/// Wire label of a garbled circuit
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WireLabel<T> {
    /// Wire id
    pub id: usize,
    /// Wire label value
    pub value: T,
}

impl WireLabel<Block> {
    pub fn random<R: Rng + CryptoRng>(id: usize, rng: &mut R) -> Self {
        Self {
            id,
            value: Block::random(rng),
        }
    }
}

/// Complete half-gate garbled circuit data, including delta which can be used to
/// derive the private inputs of the Garbler
#[derive(Clone)]
pub struct FullGarbledCircuit {
    pub circ: Arc<Circuit>,
    pub wire_labels: Vec<[Block; 2]>,
    pub public_labels: [Block; 2],
    pub table: Vec<[Block; 2]>,
    pub delta: Block,
}

#[derive(Clone)]
pub struct GarbledCircuit {
    pub circ: Arc<Circuit>,
    pub input_labels: Vec<BinaryLabel>,
    pub public_labels: [Block; 2],
    pub table: Vec<[Block; 2]>,
    pub decoding: Option<Vec<bool>>,
}

impl FullGarbledCircuit {
    pub fn decoding(&self) -> Vec<bool> {
        self.wire_labels
            .iter()
            .skip(self.circ.len() - self.circ.output_len())
            .map(|labels| labels[0].lsb() == 1)
            .collect()
    }

    pub fn to_eval(&self, input_labels: &[BinaryLabel], decoding: bool) -> GarbledCircuit {
        GarbledCircuit {
            circ: self.circ.clone(),
            input_labels: input_labels.into(),
            public_labels: self.public_labels,
            table: self.table.clone(),
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
            (label.id == id) & ((label.value == pair[0]) | (label.value == pair[1]))
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
) -> (Vec<[Block; 2]>, Block) {
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
        low.into_iter().map(|low| [low, low ^ delta]).collect(),
        delta,
    )
}

/// Generates wire labels corresponding to public truth values [0, 1]
pub fn generate_public_labels<R: Rng + CryptoRng>(rng: &mut R, delta: &Block) -> [Block; 2] {
    [Block::random(rng), Block::random(rng) ^ *delta]
}

/// Sorts an array of input labels and validates according to a circuit description.
pub fn prepare_inputs(circ: &Circuit, mut inputs: Vec<BinaryLabel>) -> Result<Vec<Block>, Error> {
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

    Ok(inputs.into_iter().map(|label| label.value).collect())
}

/// Decodes output wire labels into plaintext
pub fn decode(labels: &[Block], decoding: &[bool]) -> Vec<bool> {
    assert!(
        labels.len() == decoding.len(),
        "arrays are different length"
    );
    labels
        .iter()
        .zip(decoding)
        .map(|(label, decode)| (label.lsb() != 0) ^ decode)
        .collect()
}
