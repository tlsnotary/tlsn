//! Collection of labels corresponding to a wire group.

mod digest;
mod encoder;
pub(crate) mod input;
pub(crate) mod output;
mod set;
mod state;

use mpc_circuits::{Circuit, GroupId, GroupValue, Input, Output, Value, WireGroup};
use rand::{CryptoRng, Rng};
use std::{
    ops::{BitXor, Deref},
    sync::Arc,
};

use crate::{block::Block, garble::LabelError};

pub use digest::LabelsDigest;
pub use encoder::ChaChaEncoder;
pub use output::OutputLabelsCommitment;
pub use set::LabelsSet;

/// A collection of full labels not associated with a wire group.
pub type FullLabels = state::Full;
/// A collection of active labels not associated with a wire group.
pub type ActiveLabels = state::Active;

/// Full input labels, ie contains both the low and high labels.
pub type FullInputLabels = Labels<Input, state::Full>;
/// Active input labels of a garbled circuit. These are the labels which the evaluator uses
/// to evaluate the circuit.
pub type ActiveInputLabels = Labels<Input, state::Active>;
/// Input labels decoding information
pub type InputLabelsDecodingInfo = LabelsDecodingInfo<Input>;
/// Full output labels of a garbled circuit
pub type FullOutputLabels = Labels<Output, state::Full>;
/// Active output labels of a garbled circuit. These are the labels which the evaluator derives
/// as a result of the circuit evaluation.
pub type ActiveOutputLabels = Labels<Output, state::Active>;
/// Output labels decoding information
pub type OutputLabelsDecodingInfo = LabelsDecodingInfo<Output>;

/// A complete set of full input labels
pub type FullInputLabelsSet = LabelsSet<Input, state::Full>;
/// A complete set of full output labels
pub type FullOutputLabelsSet = LabelsSet<Output, state::Full>;
/// A complete set of active input labels
pub type ActiveInputLabelsSet = LabelsSet<Input, state::Active>;
/// A complete set of active output labels
pub type ActiveOutputLabelsSet = LabelsSet<Output, state::Active>;

/// Global binary offset used by the Free-XOR technique to create wire label
/// pairs where W_1 = W_0 ^ Delta.
///
/// In accordance with the (p&p) permute-and-point technique, the LSB of delta is set to 1 so
/// the permute bit LSB(W_1) = LSB(W_0) ^ 1
#[derive(Debug, Clone, Copy, PartialEq)]
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

impl From<[u8; 16]> for Delta {
    #[inline]
    fn from(bytes: [u8; 16]) -> Self {
        Self(Block::from(bytes))
    }
}

/// Collection of validated labels corresponding to a wire group
///
/// This type uses `Arc` references to the underlying data to make it cheap to clone,
/// and thus more memory efficient when re-using labels between garbled circuit executions.
#[derive(Debug, Clone, PartialEq)]
pub struct Labels<G, S>
where
    G: WireGroup,
    S: state::State,
{
    group: G,
    state: S,
}

impl<G, S> Labels<G, S>
where
    G: WireGroup,
    S: state::State,
{
    /// Consumes `self` returning labels
    pub fn into_labels(self) -> S {
        self.state
    }
}

impl<G> Labels<G, state::Full>
where
    G: WireGroup + Clone,
{
    /// Returns Labels type, validating the provided labels using the associated group
    pub fn from_labels(group: G, delta: Delta, labels: Vec<LabelPair>) -> Result<Self, LabelError> {
        if group.len() != labels.len() {
            return Err(LabelError::InvalidLabelCount(
                group.id().clone(),
                group.len(),
                labels.len(),
            ));
        }

        let low = labels.into_iter().map(|label| Label(label.low())).collect();

        Ok(Self {
            group,
            state: state::Full::from_labels(low, delta),
        })
    }

    /// Returns Labels type, validating the provided labels using the associated group
    pub fn from_full_labels(group: G, labels: state::Full) -> Result<Self, LabelError> {
        if group.len() != labels.len() {
            return Err(LabelError::InvalidLabelCount(
                group.id().clone(),
                group.len(),
                labels.len(),
            ));
        }

        Ok(Self {
            group,
            state: labels,
        })
    }

    /// Returns iterator to wire labels
    pub fn iter(&self) -> impl Iterator<Item = LabelPair> + '_ {
        self.state.iter()
    }

    /// Returns iterator to wire labels as blocks
    pub fn iter_blocks(&self) -> impl Iterator<Item = [Block; 2]> + '_ {
        self.iter().map(|label| [label.low(), label.high()])
    }

    /// Returns delta offset
    pub fn delta(&self) -> Delta {
        self.state.delta
    }

    /// Returns label decoding
    pub fn decoding(&self) -> LabelsDecodingInfo<G> {
        LabelsDecodingInfo {
            group: self.group.clone(),
            decoding: self
                .state
                .low
                .iter()
                .map(|label| label.permute_bit())
                .collect(),
        }
    }

    /// Returns full labels from decoding information
    pub fn from_decoding(
        active_labels: Labels<G, state::Active>,
        delta: Delta,
        decoding: LabelsDecodingInfo<G>,
    ) -> Result<Self, LabelError> {
        Ok(Self {
            group: active_labels.group,
            state: state::Full::from_decoding(active_labels.state, delta, decoding.decoding)?,
        })
    }

    /// Returns active labels corresponding to a [`Value`]
    pub fn select(&self, value: &Value) -> Result<Labels<G, state::Active>, LabelError> {
        Ok(Labels {
            group: self.group.clone(),
            state: self.state.select(value)?,
        })
    }

    /// Validates whether the provided active labels are authentic
    pub fn validate(&self, labels: &Labels<G, state::Active>) -> Result<(), LabelError> {
        for (pair, label) in self.state.iter().zip(labels.iter()) {
            if !(label.value() == pair.low() || label.value() == pair.high()) {
                return Err(LabelError::InauthenticLabels(labels.group.id().clone()));
            }
        }
        Ok(())
    }

    /// Returns wire labels
    pub fn inner(&self) -> Vec<LabelPair> {
        self.state.to_labels()
    }

    /// Returns labels as blocks
    pub fn blocks(&self) -> Vec<[Block; 2]> {
        self.inner()
            .into_iter()
            .map(|label| [label.low(), label.high()])
            .collect()
    }

    #[cfg(test)]
    /// Returns labels at position idx
    ///
    /// Panics if idx is not in range
    pub fn get(&self, idx: usize) -> LabelPair {
        self.state.get(idx)
    }

    #[cfg(test)]
    /// Set the value of labels at position idx
    ///
    /// Panics if idx is not in range
    pub fn set(&mut self, idx: usize, pair: LabelPair) {
        self.state.set(idx, pair);
    }

    #[cfg(test)]
    /// Flip a label at position idx
    ///
    /// Panics if idx is not in range
    pub fn flip(&mut self, idx: usize) {
        self.state.flip(idx);
    }
}

impl<G> Labels<G, state::Active>
where
    G: WireGroup + Clone,
{
    /// Returns Labels type, validating the provided labels using the associated group
    pub fn from_labels(group: G, labels: Vec<Label>) -> Result<Self, LabelError> {
        // We strip the labels down to blocks because the wire ids will be changed
        Self::from_blocks(
            group,
            labels.into_iter().map(|label| label.value()).collect(),
        )
    }

    /// Returns Labels type, validating the provided labels using the associated group
    pub fn from_active_labels(group: G, labels: state::Active) -> Result<Self, LabelError> {
        if group.len() != labels.len() {
            return Err(LabelError::InvalidLabelCount(
                group.id().clone(),
                group.len(),
                labels.len(),
            ));
        }

        Ok(Self {
            group,
            state: labels,
        })
    }

    /// Returns Labels type, validating the provided blocks using the associated group
    pub fn from_blocks(group: G, blocks: Vec<Block>) -> Result<Self, LabelError> {
        if group.len() != blocks.len() {
            return Err(LabelError::InvalidLabelCount(
                group.id().clone(),
                group.len(),
                blocks.len(),
            ));
        }

        let labels = blocks.into_iter().map(|block| Label::new(block)).collect();

        Ok(Self {
            group,
            state: state::Active::from_labels(labels),
        })
    }

    /// Returns iterator to wire labels
    pub fn iter(&self) -> impl Iterator<Item = Label> + '_ {
        self.state.iter()
    }

    /// Returns iterator to wire labels as blocks
    pub fn iter_blocks(&self) -> impl Iterator<Item = Block> + '_ {
        self.iter().map(|label| label.value())
    }

    /// Decode active labels to values using label decoding information.
    pub fn decode(&self, decoding: LabelsDecodingInfo<G>) -> Result<GroupValue<G>, LabelError> {
        if self.group.index() != decoding.group.index() {
            return Err(LabelError::InvalidDecodingId(
                self.group.index(),
                decoding.group.index(),
            ));
        }

        // `bits` are guaranteed to have the correct number of bits for this group
        let bits = self.state.decode(decoding.decoding)?;

        Ok(GroupValue::from_bits(self.group.clone(), bits)
            .expect("Value should have correct bit count"))
    }

    #[cfg(test)]
    /// Returns label at position idx
    ///
    /// Panics if idx is not in range
    pub fn get(&self, idx: usize) -> Label {
        self.state.get(idx)
    }

    #[cfg(test)]
    /// Set the label at position idx
    ///
    /// Panics if idx is not in range
    pub fn set(&mut self, idx: usize, label: Label) {
        self.state.set(idx, label);
    }
}

impl<G, S> WireGroup for Labels<G, S>
where
    G: WireGroup,
    S: state::State,
{
    fn circuit(&self) -> Arc<Circuit> {
        self.group.circuit()
    }

    fn index(&self) -> usize {
        self.group.index()
    }

    fn id(&self) -> &GroupId {
        self.group.id()
    }

    fn description(&self) -> &str {
        self.group.description()
    }

    fn value_type(&self) -> mpc_circuits::ValueType {
        self.group.value_type()
    }

    fn wires(&self) -> &[usize] {
        self.group.wires()
    }
}

/// Wire label of a garbled circuit
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Label(Block);

impl BitXor<Delta> for Label {
    type Output = Self;

    #[inline]
    fn bitxor(self, rhs: Delta) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl AsRef<Block> for Label {
    fn as_ref(&self) -> &Block {
        &self.0
    }
}

impl Label {
    /// Creates a new label
    #[inline]
    pub fn new(value: Block) -> Self {
        Self(value)
    }

    /// Returns inner block
    #[inline]
    pub fn to_inner(self) -> Block {
        self.0
    }

    /// Returns value of label
    #[inline]
    pub fn value(&self) -> Block {
        self.0
    }

    /// Returns label permute bit from permute-and-point technique
    #[inline]
    pub fn permute_bit(&self) -> bool {
        self.0.lsb() == 1
    }

    /// Creates a new random label
    pub fn random<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        Self(Block::random(rng))
    }

    /// Creates label pair from delta and corresponding truth value
    #[inline]
    pub fn to_pair(self, delta: Delta, level: bool) -> LabelPair {
        let (low, high) = if level {
            (self.0 ^ delta.0, self.0)
        } else {
            (self.0, self.0 ^ delta.0)
        };

        LabelPair(low, high)
    }
}

/// Pair of garbled circuit labels
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LabelPair(Block, Block);

impl LabelPair {
    /// Creates a new label pair
    #[inline]
    pub(crate) fn new(low: Block, high: Block) -> Self {
        Self(low, high)
    }

    /// Returns inner blocks
    #[inline]
    pub fn to_inner(self) -> [Block; 2] {
        [self.0, self.1]
    }

    /// Generates pairs of labels \[W_0, W_0 ^ delta\]
    pub fn generate<R: Rng + CryptoRng>(
        rng: &mut R,
        delta: Option<Delta>,
        count: usize,
    ) -> (Vec<Self>, Delta) {
        let delta = delta.unwrap_or_else(|| Delta::random(rng));
        // Logical low labels, [W_0; count]
        let low = Block::random_vec(rng, count);
        (
            low.into_iter()
                .map(|value| LabelPair::new(value, value ^ *delta))
                .collect(),
            delta,
        )
    }

    /// Returns label corresponding to logical low
    #[inline]
    pub fn low(&self) -> Block {
        self.0
    }

    /// Returns label corresponding to logical high
    #[inline]
    pub fn high(&self) -> Block {
        self.1
    }

    /// Returns label corresponding to provided logic level
    #[inline]
    pub fn select(&self, level: bool) -> Label {
        let block = if level { &self.1 } else { &self.0 };
        Label::new(*block)
    }

    /// Returns labels corresponding to wire truth values
    ///
    /// Panics if wire is not in label collection
    pub fn choose(labels: &[LabelPair], wires: &[usize], values: &[bool]) -> Vec<Label> {
        wires
            .iter()
            .zip(values.iter())
            .map(|(id, value)| labels[*id].select(*value))
            .collect()
    }
}

/// Decoding info for garbled circuit wire labels.
///
/// W_1 = W_0 ^ Delta where LSB(Delta) = 1
///
/// thus LSB(W_1) = LSB(W_0) ^ LSB(Delta) = LSB(W_0) ^ 1
///
/// To determine the truth value of a wire label W, we simply compute:
///
/// Decode(W) = LSB(W) ^ DecodingInfo(W)
///
/// where DecodingInfo(W) = LSB(W_0).
#[derive(Debug, Clone, PartialEq)]
pub struct LabelsDecodingInfo<G>
where
    G: WireGroup,
{
    group: G,
    pub(crate) decoding: Vec<bool>,
}

impl<G> LabelsDecodingInfo<G>
where
    G: WireGroup,
{
    /// Returns label id
    pub fn id(&self) -> usize {
        self.group.index()
    }
}

/// Extracts active labels from a (sorted) slice containing all active labels
/// for a garbled circuit
///
/// Panics if provided an invalid group
pub(crate) fn extract_active_labels<G: WireGroup + Clone>(
    groups: &[G],
    labels: &[Label],
) -> Vec<Labels<G, state::Active>> {
    groups
        .iter()
        .map(|group| {
            let labels = group
                .wires()
                .iter()
                .copied()
                .map(|wire_id| labels[wire_id])
                .collect();
            Labels::<G, state::Active>::from_labels(group.clone(), labels)
                .expect("Labels should be valid")
        })
        .collect()
}

/// Extracts full labels from a (sorted) slice containing all full labels
/// for a garbled circuit
///
/// Panics if provided an invalid group
pub(crate) fn extract_full_labels<G: WireGroup + Clone>(
    groups: &[G],
    delta: Delta,
    labels: &[LabelPair],
) -> Vec<Labels<G, state::Full>> {
    groups
        .iter()
        .map(|group| {
            let labels = group
                .wires()
                .iter()
                .copied()
                .map(|wire_id| labels[wire_id])
                .collect();
            Labels::<G, state::Full>::from_labels(group.clone(), delta, labels)
                .expect("Labels should be valid")
        })
        .collect()
}

/// Decodes set of active wire labels
pub(crate) fn decode_active_labels<G: WireGroup + Clone>(
    labels: &[Labels<G, state::Active>],
    decoding: &[LabelsDecodingInfo<G>],
) -> Result<Vec<GroupValue<G>>, LabelError> {
    labels
        .iter()
        .zip(decoding.to_vec())
        .map(|(labels, decoding)| labels.decode(decoding))
        .collect::<Result<Vec<_>, LabelError>>()
}

pub(crate) mod unchecked {
    use super::*;
    use mpc_circuits::WireGroup;

    #[derive(Debug, Clone)]
    pub struct UncheckedLabelsDecodingInfo {
        pub(crate) id: usize,
        pub(crate) decoding: Vec<bool>,
    }

    #[cfg(test)]
    impl<G> From<LabelsDecodingInfo<G>> for UncheckedLabelsDecodingInfo
    where
        G: WireGroup,
    {
        fn from(decoding: LabelsDecodingInfo<G>) -> Self {
            Self {
                id: decoding.group.index(),
                decoding: decoding.decoding,
            }
        }
    }

    impl<G> LabelsDecodingInfo<G>
    where
        G: WireGroup,
    {
        /// Validates and converts to checked variant
        pub fn from_unchecked(
            group: G,
            unchecked: UncheckedLabelsDecodingInfo,
        ) -> Result<Self, LabelError> {
            if group.index() != unchecked.id {
                return Err(LabelError::InvalidDecodingId(group.index(), unchecked.id));
            } else if group.len() != unchecked.decoding.len() {
                return Err(LabelError::InvalidDecodingCount(
                    group.len(),
                    unchecked.decoding.len(),
                ));
            }

            Ok(Self {
                group,
                decoding: unchecked.decoding,
            })
        }
    }

    #[cfg(test)]
    mod test {
        use super::*;
        use rstest::*;

        use mpc_circuits::{Circuit, ADDER_64};

        #[fixture]
        fn circ() -> Arc<Circuit> {
            Circuit::load_bytes(ADDER_64).unwrap()
        }

        #[fixture]
        fn output(circ: Arc<Circuit>) -> Output {
            circ.output(0).unwrap()
        }

        #[fixture]
        fn unchecked_labels_decoding_info(output: Output) -> UncheckedLabelsDecodingInfo {
            UncheckedLabelsDecodingInfo {
                id: output.index(),
                decoding: vec![false; output.len()],
            }
        }

        #[rstest]
        fn test_labels_decoding_info(
            output: Output,
            unchecked_labels_decoding_info: UncheckedLabelsDecodingInfo,
        ) {
            LabelsDecodingInfo::from_unchecked(output, unchecked_labels_decoding_info).unwrap();
        }

        #[rstest]
        fn test_output_labels_decoding_info_wrong_id(
            output: Output,
            mut unchecked_labels_decoding_info: UncheckedLabelsDecodingInfo,
        ) {
            unchecked_labels_decoding_info.id += 1;
            let err = LabelsDecodingInfo::from_unchecked(output, unchecked_labels_decoding_info)
                .unwrap_err();
            assert!(matches!(err, LabelError::InvalidDecodingId(_, _)))
        }

        #[rstest]
        fn test_output_labels_decoding_info_wrong_count(
            output: Output,
            mut unchecked_labels_decoding_info: UncheckedLabelsDecodingInfo,
        ) {
            unchecked_labels_decoding_info.decoding.pop();
            let err = LabelsDecodingInfo::from_unchecked(output, unchecked_labels_decoding_info)
                .unwrap_err();
            assert!(matches!(err, LabelError::InvalidDecodingCount(_, _)))
        }
    }
}
