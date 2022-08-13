use rand::{CryptoRng, Rng};
use std::{collections::HashSet, ops::Deref};

use crate::{
    block::Block,
    garble::{Error, InputError},
    utils::pick,
};
use mpc_circuits::{Circuit, Input, InputValue};

/// Global binary offset used by the Free-XOR technique to create wire label
/// pairs where W_1 = W_0 ^ Delta.
///
/// In accordance with the (p&p) permute-and-point technique, the LSB of delta is set to 1 so
/// the permute bit LSB(W_1) = LSB(W_0) ^ 1
#[derive(Debug, Clone, Copy)]
pub struct Delta(Block);

impl Delta {
    /// Creates new random Delta
    pub(crate) fn random<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        let mut block = Block::random(rng);
        block.set_lsb();
        Self(block)
    }
}

impl Deref for Delta {
    type Target = Block;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Wire label of a garbled circuit
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WireLabel {
    /// Wire id
    id: usize,
    /// Wire label which corresponds to the logical level of a circuit wire
    value: Block,
}

impl AsRef<Block> for WireLabel {
    fn as_ref(&self) -> &Block {
        &self.value
    }
}

impl WireLabel {
    /// Creates a new wire label
    #[inline]
    pub(crate) fn new(id: usize, value: Block) -> Self {
        Self { id, value }
    }

    /// Returns wire id of label
    #[inline]
    pub fn id(&self) -> usize {
        self.id
    }

    /// Returns wire label permute bit from permute-and-point technique
    #[inline]
    pub fn permute_bit(&self) -> bool {
        self.value.lsb() == 1
    }

    /// Creates a new random wire label
    pub fn random<R: Rng + CryptoRng>(id: usize, rng: &mut R) -> Self {
        Self {
            id,
            value: Block::random(rng),
        }
    }
}

/// Pair of garbled circuit wire labels
#[derive(Debug, Clone, Copy)]
pub struct WireLabelPair {
    /// Wire id
    id: usize,
    /// Wire label which corresponds to logical LOW of a circuit wire
    low: Block,
    /// Wire label which corresponds to logical HIGH of a circuit wire
    high: Block,
}

impl WireLabelPair {
    /// Creates a new wire label pair
    #[inline]
    pub(crate) fn new(id: usize, low: Block, high: Block) -> Self {
        Self { id, low, high }
    }

    /// Returns wire id
    #[inline]
    pub fn id(&self) -> usize {
        self.id
    }

    /// Returns wire label corresponding to logical low
    #[inline]
    pub fn low(&self) -> &Block {
        &self.low
    }

    /// Returns wire label corresponding to logical high
    #[inline]
    pub fn high(&self) -> &Block {
        &self.high
    }

    /// Returns wire labels corresponding to provided logic level
    #[inline]
    pub fn select(&self, level: bool) -> WireLabel {
        let block = if level { &self.high } else { &self.low };
        WireLabel::new(self.id, *block)
    }

    /// Returns wire labels corresponding to wire truth values
    ///
    /// Panics if wire is not in label collection
    pub fn choose(labels: &[WireLabelPair], wires: &[usize], values: &[bool]) -> Vec<WireLabel> {
        wires
            .iter()
            .zip(values.iter())
            .map(|(id, value)| labels[*id].select(*value))
            .collect()
    }
}

/// Wire labels corresponding to a circuit input
#[derive(Debug, Clone)]
pub struct InputLabels<T> {
    input: Input,
    labels: Vec<T>,
}

impl<T: Copy> InputLabels<T> {
    pub(crate) fn new(input: Input, labels: &[T]) -> Self {
        debug_assert_eq!(input.as_ref().len(), labels.len());
        Self {
            input,
            labels: labels.to_vec(),
        }
    }

    pub fn id(&self) -> usize {
        self.input.id
    }
}

impl InputLabels<WireLabelPair> {
    /// Returns input wire labels corresponding to an [`InputValue`]
    pub fn select(&self, value: &InputValue) -> Result<InputLabels<WireLabel>, Error> {
        // TODO: Don't panic, return proper error
        assert_eq!(value.id(), self.input.id);

        let labels: Vec<WireLabel> = self
            .labels
            .iter()
            .zip(value.as_ref().iter())
            .map(|(pair, value)| pair.select(*value))
            .collect();

        Ok(InputLabels {
            input: self.input.clone(),
            labels,
        })
    }
}

impl<T> AsRef<[T]> for InputLabels<T> {
    fn as_ref(&self) -> &[T] {
        &self.labels
    }
}

/// Input labels that have been sanitized are safe to use to evaluate a garbled circuit
///
/// It is important to check that the generator has provided the expected input labels,
/// otherwise they may have an opportunity to behave maliciously to extract the evaluator's
/// private inputs.
#[derive(Debug, Clone)]
pub struct SanitizedInputLabels(Vec<WireLabel>);

impl SanitizedInputLabels {
    pub(crate) fn new(
        circ: &Circuit,
        gen_labels: &[InputLabels<WireLabel>],
        ev_labels: &[InputLabels<WireLabel>],
    ) -> Result<Self, Error> {
        let gen_ids: HashSet<usize> = gen_labels.iter().map(|labels| labels.id()).collect();
        let ev_ids: HashSet<usize> = ev_labels.iter().map(|labels| labels.id()).collect();

        // Error if there are duplicate inputs
        if !gen_ids.is_disjoint(&ev_ids) {
            return Err(Error::InvalidInput(InputError::Duplicate));
        }

        // Error if wrong number of inputs are provided
        if circ.input_count() != gen_ids.len() + ev_ids.len() {
            return Err(Error::InvalidInput(InputError::InvalidCount(
                circ.input_count(),
                gen_ids.len() + ev_ids.len(),
            )));
        }

        let mut labels: Vec<WireLabel> = gen_labels
            .iter()
            .chain(ev_labels.iter())
            .map(|labels| labels.as_ref())
            .flatten()
            .copied()
            .collect();

        labels.sort_by_key(|label| label.id);
        labels.dedup_by_key(|label| label.id);

        // Error if input labels contain duplicate wire ids
        if circ.input_len() != labels.len() {
            return Err(Error::InvalidInput(InputError::Duplicate));
        }

        Ok(Self(labels))
    }

    /// Consumes `self` returning the inner input labels
    pub(crate) fn inner(self) -> Vec<WireLabel> {
        self.0
    }
}

/// Generates pairs of wire labels \[W_0, W_0 ^ delta\]
pub fn generate_label_pairs<R: Rng + CryptoRng>(
    rng: &mut R,
    delta: Option<Delta>,
    count: usize,
    offset: usize,
) -> (Vec<WireLabelPair>, Delta) {
    let delta = match delta {
        Some(delta) => delta,
        None => Delta::random(rng),
    };
    // Logical low wire labels, [W_0; count]
    let low = Block::random_vec(rng, count);
    (
        low.into_iter()
            .enumerate()
            .map(|(id, value)| WireLabelPair::new(id + offset, value, value ^ *delta))
            .collect(),
        delta,
    )
}

/// Generates a full set of input [`WireLabelPair`] for the provided [`Circuit`]
pub fn generate_input_labels<R: Rng + CryptoRng>(
    rng: &mut R,
    circ: &Circuit,
    delta: Option<Delta>,
) -> (Vec<InputLabels<WireLabelPair>>, Delta) {
    let (labels, delta) = generate_label_pairs(rng, delta, circ.input_len(), 0);

    // This should never panic due to invariants enforced during the construction of a `Circuit`
    let inputs: Vec<InputLabels<WireLabelPair>> = circ
        .inputs()
        .iter()
        .map(|input| InputLabels::new(input.clone(), &pick(&labels, input.as_ref().wires())))
        .collect();

    (inputs, delta)
}

/// Decodes output wire labels into plaintext.
///
/// Thanks to the permute-and-point (p&p) technique, the two adjacent labels
/// will have the opposite p&p bits. We apply the decoding to the p&p bits.
pub fn decode_labels(labels: &[WireLabel], decoding: &[bool]) -> Result<Vec<bool>, Error> {
    if labels.len() != decoding.len() {
        return Err(Error::InvalidLabelDecoding);
    }
    Ok(labels
        .iter()
        .zip(decoding)
        .map(|(label, decode_bit)| decode(label, *decode_bit))
        .collect())
}

/// Decodes a wire label using it's point-and-permute bit.
#[inline]
pub fn decode(label: &WireLabel, decode_bit: bool) -> bool {
    label.permute_bit() ^ decode_bit
}
