use rand::{CryptoRng, Rng};
use std::{collections::HashSet, ops::Deref};

use crate::{
    block::Block,
    garble::{Error, InputError},
    utils::pick,
};
use mpc_circuits::{Circuit, Input, InputValue, Output, OutputValue};

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
    /// Wire label which corresponds to the logical level (low/high) of a circuit wire
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
    pub fn new(id: usize, value: Block) -> Self {
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

    /// Decodes wire label to its corresponding truth value
    #[inline]
    pub fn decode(&self, encoding: LabelEncoding) -> bool {
        self.permute_bit() ^ *encoding
    }

    /// Decodes output wire labels into plaintext.
    ///
    /// Thanks to the permute-and-point (p&p) technique, the two adjacent labels
    /// will have the opposite p&p bits. We apply the encoding to the p&p bits.
    pub fn decode_many(labels: &[Self], encoding: &[LabelEncoding]) -> Result<Vec<bool>, Error> {
        if labels.len() != encoding.len() {
            return Err(Error::InvalidLabelEncoding);
        }
        Ok(labels
            .iter()
            .zip(encoding)
            .map(|(label, encoding)| label.decode(*encoding))
            .collect())
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

    /// Generates pairs of wire labels \[W_0, W_0 ^ delta\]
    pub fn generate<R: Rng + CryptoRng>(
        rng: &mut R,
        delta: Option<Delta>,
        count: usize,
        offset: usize,
    ) -> (Vec<Self>, Delta) {
        let delta = delta.unwrap_or_else(|| Delta::random(rng));
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
    pub input: Input,
    labels: Vec<T>,
}

impl<T: Copy> InputLabels<T> {
    pub fn new(input: Input, labels: &[T]) -> Result<Self, Error> {
        if input.as_ref().len() != labels.len() {
            return Err(Error::InvalidInputLabels);
        }

        Ok(Self {
            input,
            labels: labels.to_vec(),
        })
    }

    pub fn id(&self) -> usize {
        self.input.id
    }
}

impl InputLabels<WireLabelPair> {
    /// Generates a full set of input [`WireLabelPair`] for the provided [`Circuit`]
    pub fn generate<R: Rng + CryptoRng>(
        rng: &mut R,
        circ: &Circuit,
        delta: Option<Delta>,
    ) -> (Vec<Self>, Delta) {
        let (labels, delta) = WireLabelPair::generate(rng, delta, circ.input_len(), 0);

        // This should never panic due to invariants enforced during the construction of a `Circuit`
        let inputs: Vec<InputLabels<WireLabelPair>> = circ
            .inputs()
            .iter()
            .map(|input| {
                InputLabels::new(input.clone(), &pick(&labels, input.as_ref().wires()))
                    .expect("Circuit invariant violated, wrong wire count")
            })
            .collect();

        (inputs, delta)
    }

    /// Generates a full set of input [`WireLabelPair`] for the provided [`Circuit`], split by provided input ids.
    /// The first collection corresponds to the provided ids, the other collection is the remainder.
    pub fn generate_split<R: Rng + CryptoRng>(
        rng: &mut R,
        circ: &Circuit,
        input_ids: &[usize],
        delta: Option<Delta>,
    ) -> Result<((Vec<Self>, Vec<Self>), Delta), Error> {
        let mut input_ids = input_ids.to_vec();
        input_ids.sort();
        input_ids.dedup();

        // Check input ids are valid
        for id in input_ids.iter() {
            _ = circ.input(*id)?
        }

        let (labels, delta) = Self::generate(rng, circ, delta);

        let (left, right): (Vec<Self>, Vec<Self>) = labels
            .into_iter()
            .partition(|labels| input_ids.contains(&labels.id()));

        Ok(((left, right), delta))
    }

    /// Returns input wire labels corresponding to an [`InputValue`]
    pub fn select(&self, value: &InputValue) -> Result<InputLabels<WireLabel>, Error> {
        // TODO: Don't panic, return proper error
        assert_eq!(value.id(), self.input.id);

        let labels: Vec<WireLabel> = self
            .labels
            .iter()
            .zip(value.wire_values())
            .map(|(pair, value)| pair.select(value))
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
        let label_count = labels.len();
        labels.dedup_by_key(|label| label.id);

        // Error if input labels contain duplicate wire ids
        if label_count != labels.len() {
            return Err(Error::InvalidInput(InputError::Duplicate));
        }

        // Error if incorrect number of input wires
        if label_count != circ.input_len() {
            return Err(Error::InvalidInput(InputError::InvalidWireCount(
                circ.input_len(),
                label_count,
            )));
        }

        Ok(Self(labels))
    }

    /// Consumes `self` returning the inner input labels
    pub(crate) fn inner(self) -> Vec<WireLabel> {
        self.0
    }
}

/// Wire labels corresponding to a circuit output
#[derive(Debug, Clone)]
pub struct OutputLabels<T> {
    pub output: Output,
    labels: Vec<T>,
}

impl<T: Copy> OutputLabels<T> {
    pub fn new(output: Output, labels: &[T]) -> Result<Self, Error> {
        if output.as_ref().len() != labels.len() {
            return Err(Error::InvalidOutputLabels);
        }

        Ok(Self {
            output,
            labels: labels.to_vec(),
        })
    }

    pub fn id(&self) -> usize {
        self.output.id
    }
}

impl OutputLabels<WireLabelPair> {
    /// Returns output labels encoding
    pub(crate) fn encode(&self) -> OutputLabelsEncoding {
        OutputLabelsEncoding::from_labels(self)
    }

    /// Returns output wire labels corresponding to an [`OutputValue`]
    pub fn select(&self, value: &OutputValue) -> Result<OutputLabels<WireLabel>, Error> {
        // TODO: Don't panic, return proper error
        assert_eq!(value.id(), self.output.id);

        let labels: Vec<WireLabel> = self
            .labels
            .iter()
            .zip(value.wire_values())
            .map(|(pair, value)| pair.select(value))
            .collect();

        Ok(OutputLabels {
            output: self.output.clone(),
            labels,
        })
    }

    /// Validates whether the provided output labels are authentic according to
    /// a full set of labels.
    pub fn validate(&self, labels: &OutputLabels<WireLabel>) -> Result<(), Error> {
        for (pair, label) in self.labels.iter().zip(&labels.labels) {
            if label.value == *pair.low() || label.value == *pair.high() {
                continue;
            } else {
                return Err(Error::InvalidOutputLabels);
            }
        }
        Ok(())
    }
}

impl OutputLabels<WireLabel> {
    /// Decodes output wire labels
    pub(crate) fn decode(&self, encoding: &OutputLabelsEncoding) -> Result<OutputValue, Error> {
        if encoding.output != self.output {
            return Err(Error::InvalidLabelEncoding);
        }
        Ok(self
            .output
            .parse_bits(WireLabel::decode_many(&self.labels, encoding.as_ref())?)?)
    }

    /// Convenience function to convert labels into bytes
    pub(crate) fn to_be_bytes(&self) -> Vec<u8> {
        self.labels
            .iter()
            .map(|label| label.as_ref().to_be_bytes())
            .flatten()
            .collect()
    }
}

impl<T> AsRef<[T]> for OutputLabels<T> {
    fn as_ref(&self) -> &[T] {
        &self.labels
    }
}

/// Encoding of garbled circuit wire label.
///
/// W_1 = W_0 ^ Delta where LSB(Delta) = 1
///
/// thus LSB(W_1) = LSB(W_0) ^ LSB(Delta) = LSB(W_0) ^ 1
///
/// To determine the truth value of a wire label W, we simply compute:
///
/// Decode(W) = LSB(W) ^ Encode(W)
///
/// where Encode(W) = LSB(W_0).
#[derive(Debug, Clone, Copy)]
pub struct LabelEncoding(bool);

impl Deref for LabelEncoding {
    type Target = bool;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// For details about label encoding see [`LabelEncoding`]
#[derive(Debug, Clone)]
pub struct OutputLabelsEncoding {
    pub output: Output,
    encoding: Vec<LabelEncoding>,
}

impl OutputLabelsEncoding {
    pub(crate) fn new(output: Output, encoding: Vec<bool>) -> Result<Self, Error> {
        if output.as_ref().len() != encoding.len() {
            return Err(Error::InvalidLabelEncoding);
        }

        Ok(Self {
            output,
            encoding: encoding.into_iter().map(|enc| LabelEncoding(enc)).collect(),
        })
    }

    fn from_labels(labels: &OutputLabels<WireLabelPair>) -> Self {
        Self {
            output: labels.output.clone(),
            encoding: labels
                .labels
                .iter()
                .map(|label| LabelEncoding(label.low().lsb() == 1))
                .collect::<Vec<LabelEncoding>>(),
        }
    }
}

impl AsRef<[LabelEncoding]> for OutputLabelsEncoding {
    fn as_ref(&self) -> &[LabelEncoding] {
        &self.encoding
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;

    use mpc_circuits::{Circuit, ADDER_64};
    use rand::thread_rng;

    #[fixture]
    pub fn circ() -> Circuit {
        Circuit::load_bytes(ADDER_64).unwrap()
    }

    #[rstest]
    fn test_sanitized_labels_dup(circ: Circuit) {
        let (labels, _) = InputLabels::generate(&mut thread_rng(), &circ, None);
        let input_values = [
            circ.input(0).unwrap().to_value(0u64).unwrap(),
            circ.input(1).unwrap().to_value(0u64).unwrap(),
        ];

        // Generator provides labels for both inputs, this is a no no
        let gen_labels = [
            labels[0].clone().select(&input_values[0]).unwrap(),
            labels[1].clone().select(&input_values[1]).unwrap(),
        ];
        let ev_labels = [labels[0].clone().select(&input_values[0]).unwrap()];

        assert!(matches!(
            SanitizedInputLabels::new(&circ, &gen_labels, &ev_labels),
            Err(Error::InvalidInput(InputError::Duplicate))
        ))
    }

    #[rstest]
    fn test_sanitized_labels_wrong_count(circ: Circuit) {
        let (labels, _) = InputLabels::generate(&mut thread_rng(), &circ, None);
        let input_values = [
            circ.input(0).unwrap().to_value(0u64).unwrap(),
            circ.input(1).unwrap().to_value(0u64).unwrap(),
        ];

        // Generator provides no labels
        let gen_labels = [];
        let ev_labels = [labels[0].clone().select(&input_values[0]).unwrap()];

        assert!(matches!(
            SanitizedInputLabels::new(&circ, &gen_labels, &ev_labels),
            Err(Error::InvalidInput(InputError::InvalidCount(2, 1)))
        ));

        // Evaluator provides no labels
        let gen_labels = [labels[0].clone().select(&input_values[0]).unwrap()];
        let ev_labels = [];

        assert!(matches!(
            SanitizedInputLabels::new(&circ, &gen_labels, &ev_labels),
            Err(Error::InvalidInput(InputError::InvalidCount(2, 1)))
        ));
    }

    #[rstest]
    fn test_sanitized_labels_duplicate_wires(circ: Circuit) {
        let (labels, _) = InputLabels::generate(&mut thread_rng(), &circ, None);
        let input_values = [
            circ.input(0).unwrap().to_value(0u64).unwrap(),
            circ.input(1).unwrap().to_value(0u64).unwrap(),
        ];

        let mut input_labels = [
            labels[0].clone().select(&input_values[0]).unwrap(),
            labels[1].clone().select(&input_values[1]).unwrap(),
        ];

        // Somehow manages to get an overlapping label id here
        input_labels[1].labels[0].id = 0;

        let gen_labels = [input_labels[1].clone()];
        let ev_labels = [input_labels[0].clone()];

        assert!(matches!(
            SanitizedInputLabels::new(&circ, &gen_labels, &ev_labels),
            Err(Error::InvalidInput(InputError::Duplicate))
        ));

        let mut input_labels = [
            labels[0].clone().select(&input_values[0]).unwrap(),
            labels[1].clone().select(&input_values[1]).unwrap(),
        ];

        // Somehow manages to get an extra wire label here which overwrites another label
        input_labels[1]
            .labels
            .push(WireLabel::new(0, crate::Block::new(0)));

        let gen_labels = [input_labels[1].clone()];
        let ev_labels = [input_labels[0].clone()];

        assert!(matches!(
            SanitizedInputLabels::new(&circ, &gen_labels, &ev_labels),
            Err(Error::InvalidInput(InputError::Duplicate))
        ));
    }

    #[rstest]
    fn test_sanitized_labels_invalid_wire_count(circ: Circuit) {
        let (labels, _) = InputLabels::generate(&mut thread_rng(), &circ, None);
        let input_values = [
            circ.input(0).unwrap().to_value(0u64).unwrap(),
            circ.input(1).unwrap().to_value(0u64).unwrap(),
        ];

        let mut input_labels = [
            labels[0].clone().select(&input_values[0]).unwrap(),
            labels[1].clone().select(&input_values[1]).unwrap(),
        ];

        // Somehow manages to get an input missing a wire label here
        input_labels[1].labels.pop();

        let gen_labels = [input_labels[1].clone()];
        let ev_labels = [input_labels[0].clone()];

        assert!(matches!(
            SanitizedInputLabels::new(&circ, &gen_labels, &ev_labels),
            Err(Error::InvalidInput(InputError::InvalidWireCount(_, _)))
        ));

        let mut input_labels = [
            labels[0].clone().select(&input_values[0]).unwrap(),
            labels[1].clone().select(&input_values[1]).unwrap(),
        ];

        // Somehow manages to get an extra wire label here
        input_labels[1]
            .labels
            .push(WireLabel::new(usize::MAX, crate::Block::new(0)));

        let gen_labels = [input_labels[1].clone()];
        let ev_labels = [input_labels[0].clone()];

        assert!(matches!(
            SanitizedInputLabels::new(&circ, &gen_labels, &ev_labels),
            Err(Error::InvalidInput(InputError::InvalidWireCount(_, _)))
        ));
    }
}
