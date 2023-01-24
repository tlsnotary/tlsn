//! Types associated with wire labels

mod digest;
pub(crate) mod encoded;
mod encoder;
pub(crate) mod input;
pub(crate) mod output;
mod set;

use std::{
    ops::{BitAnd, BitXor, Deref},
    sync::Arc,
};

use mpc_circuits::{Input, Output, Value};
use rand::{CryptoRng, Rng};

use crate::{block::Block, garble::EncodingError};

pub use digest::LabelsDigest;
pub use encoded::{Encoded, GroupDecodingInfo};
pub use encoder::{ChaChaEncoder, Encoder, EncoderRng};
pub use output::OutputLabelsCommitment;
pub use set::EncodedSet;

/// A collection of full labels not associated with a wire group.
pub type FullLabels = Labels<Full>;
/// A collection of active labels not associated with a wire group.
pub type ActiveLabels = Labels<Active>;

/// Full input labels, ie contains both the low and high labels, corresponding to a
/// garbled circuit input.
pub type FullEncodedInput = Encoded<Input, Full>;
/// Active input labels corresponding to a garbled circuit input. These are the labels
/// which the evaluator uses to evaluate a garbled circuit.
pub type ActiveEncodedInput = Encoded<Input, Active>;
/// Input decoding information.
pub type InputDecodingInfo = GroupDecodingInfo<Input>;
/// Full output labels corresponding to a garbled circuit output.
pub type FullEncodedOutput = Encoded<Output, Full>;
/// Active output labels corresponding to a garbled circuit output. These are the labels
/// which the evaluator derives as a result of the circuit evaluation.
pub type ActiveEncodedOutput = Encoded<Output, Active>;
/// Output decoding information.
pub type OutputDecodingInfo = GroupDecodingInfo<Output>;

/// A complete set of full input labels for the inputs of a garbled circuit.
pub type FullInputSet = EncodedSet<Input, Full>;
/// A complete set of full output labels for the outputs of a garbled circuit.
pub type FullOutputSet = EncodedSet<Output, Full>;
/// A complete set of active input labels for the inputs of a garbled circuit.
pub type ActiveInputSet = EncodedSet<Input, Active>;
/// A complete set of active output labels for the outputs of a garbled circuit.
pub type ActiveOutputSet = EncodedSet<Output, Active>;

/// Global binary offset used by the Free-XOR technique to create wire label
/// pairs where W_1 = W_0 ^ Delta.
///
/// In accordance with the (p&p) permute-and-point technique, the LSB of delta is set to 1 so
/// the permute bit LSB(W_1) = LSB(W_0) ^ 1
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Delta(Block);

impl Delta {
    /// Creates new random Delta
    pub(crate) fn random<R: Rng + CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut block = Block::random(rng);
        block.set_lsb();
        Self(block)
    }

    /// Returns the inner block
    #[inline]
    pub(crate) fn into_inner(self) -> Block {
        self.0
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

pub mod state {
    use super::Delta;

    mod sealed {
        pub trait Sealed {}

        impl Sealed for super::Full {}
        impl Sealed for super::Active {}
    }

    /// Marker trait for label state
    pub trait LabelState: sealed::Sealed {}

    /// Full label state, ie contains both the low and high labels.
    #[derive(Debug, Clone, Copy, PartialEq)]
    pub struct Full {
        pub(super) delta: Delta,
    }

    impl LabelState for Full {}

    /// Active label state
    #[derive(Debug, Clone, Copy, PartialEq)]
    pub struct Active;

    impl LabelState for Active {}
}

use state::*;

/// A collection of labels, unassociated with a wire group.
///
/// This type uses an `Arc` reference to the underlying data to make it cheap to clone,
/// and thus more memory efficient when re-using labels between garbled circuit executions.
#[derive(Debug, Clone, PartialEq)]
pub struct Labels<S: LabelState> {
    state: S,
    labels: Arc<Vec<Label>>,
}

impl<S> Labels<S>
where
    S: LabelState,
{
    /// Returns number of labels
    pub fn len(&self) -> usize {
        self.labels.len()
    }
}

impl Labels<Full> {
    /// Creates new full labels from the provided low labels and delta
    ///
    /// * `low` - Labels corresponding to the logical low
    /// * `delta` - Global binary offset
    pub fn new_full(low: Vec<Label>, delta: Delta) -> Self {
        Self {
            state: Full { delta },
            labels: Arc::new(low),
        }
    }

    /// Creates new full labels from the provided blocks and delta
    ///
    /// * `blocks` - Blocks corresponding to the logical low
    /// * `delta` - Global binary offset
    pub fn from_blocks(blocks: Vec<Block>, delta: Delta) -> Self {
        Self {
            state: Full { delta },
            labels: Arc::new(blocks.into_iter().map(|block| Label(block)).collect()),
        }
    }

    /// Returns iterator of label pairs
    pub fn iter(&self) -> impl Iterator<Item = LabelPair> + '_ {
        self.labels
            .iter()
            .copied()
            .map(|low| low.to_pair(self.state.delta, false))
    }

    /// Returns delta
    pub fn get_delta(&self) -> Delta {
        self.state.delta
    }

    /// Returns label decoding information
    pub fn get_decoding(&self) -> Vec<bool> {
        self.labels.iter().map(|low| low.permute_bit()).collect()
    }

    /// Generates labels using the provided RNG.
    pub fn generate<R: Rng + CryptoRng + ?Sized>(
        rng: &mut R,
        count: usize,
        delta: Option<Delta>,
    ) -> Self {
        let delta = delta.unwrap_or_else(|| Delta::random(rng));

        // Logical low wire labels, [W_0; count]
        let low = Block::random_vec(rng, count)
            .into_iter()
            .map(|value| Label::new(value))
            .collect();

        Self {
            state: Full { delta },
            labels: Arc::new(low),
        }
    }

    /// Returns active labels corresponding to the `value`
    pub fn select(&self, value: &Value) -> Result<ActiveLabels, EncodingError> {
        if value.len() != self.labels.len() {
            return Err(EncodingError::InvalidValue(self.len(), value.len()));
        }

        let active_labels = self
            .labels
            .iter()
            .copied()
            .zip(value.to_lsb0_bits().into_iter())
            .map(|(low, level)| if level { low ^ self.get_delta() } else { low })
            .collect::<Vec<_>>();

        Ok(Labels {
            state: Active,
            labels: Arc::new(active_labels),
        })
    }

    pub(crate) fn from_decoding(
        active: Labels<Active>,
        delta: Delta,
        decoding: Vec<bool>,
    ) -> Result<Self, EncodingError> {
        if active.labels.len() != decoding.len() {
            return Err(EncodingError::InvalidDecodingLength(
                active.labels.len(),
                decoding.len(),
            ));
        }

        Ok(Self {
            state: Full { delta },
            labels: Arc::new(
                active
                    .iter()
                    .zip(decoding)
                    .map(|(label, decoding)| {
                        // If active label is logic high, flip it
                        if label.permute_bit() ^ decoding {
                            label ^ delta
                        } else {
                            label
                        }
                    })
                    .collect(),
            ),
        })
    }

    #[cfg(test)]
    pub fn get(&self, idx: usize) -> LabelPair {
        self.labels[idx].to_pair(self.state.delta, false)
    }

    #[cfg(test)]
    pub fn set(&mut self, idx: usize, pair: LabelPair) {
        let mut labels = (*self.labels).clone();
        labels[idx] = pair.low();
        self.labels = Arc::new(labels);
    }

    #[cfg(test)]
    pub fn flip(&mut self, idx: usize) {
        let mut labels = (*self.labels).clone();
        labels[idx] = labels[idx] ^ self.get_delta();
        self.labels = Arc::new(labels);
    }
}

impl Labels<Active> {
    /// Creates new active labels from the provided labels
    ///
    /// * `active` - Labels corresponding to the an active value
    pub fn new_active(active: Vec<Label>) -> Labels<Active> {
        Self {
            state: Active,
            labels: Arc::new(active),
        }
    }

    /// Creates new active labels from the provided blocks
    ///
    /// * `blocks` - Blocks corresponding to the logical low
    pub fn from_blocks(blocks: Vec<Block>) -> Self {
        Self {
            state: Active,
            labels: Arc::new(blocks.into_iter().map(|block| Label(block)).collect()),
        }
    }

    /// Returns iterator to wire labels
    pub fn iter(&self) -> impl Iterator<Item = Label> + '_ {
        self.labels.iter().copied()
    }

    /// Returns iterator to wire labels as blocks
    pub fn iter_blocks(&self) -> impl Iterator<Item = Block> + '_ {
        self.iter().map(|label| label.into_inner())
    }

    /// Decodes active labels using decoding information
    pub fn decode(&self, decoding: Vec<bool>) -> Result<Vec<bool>, EncodingError> {
        if self.len() != decoding.len() {
            return Err(EncodingError::InvalidDecodingLength(
                self.len(),
                decoding.len(),
            ));
        }

        Ok(decoding
            .into_iter()
            .zip(self.labels.iter())
            .map(|(decoding, label)| label.permute_bit() ^ decoding)
            .collect())
    }

    /// Returns label at position idx
    ///
    /// Panics if idx is not in range
    #[cfg(test)]
    pub fn get(&self, idx: usize) -> Label {
        self.labels[idx].clone()
    }

    /// Set the label at position idx
    ///
    /// Panics if idx is not in range
    #[cfg(test)]
    pub fn set(&mut self, idx: usize, label: Label) {
        let mut labels = (*self.labels).clone();
        labels[idx] = label;
        self.labels = Arc::new(labels);
    }
}

impl IntoIterator for Labels<Active> {
    type Item = Label;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        (*self.labels).clone().into_iter()
    }
}

/// Wire label of a garbled circuit
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Label(Block);

impl BitXor<Label> for Label {
    type Output = Self;

    #[inline]
    fn bitxor(self, rhs: Label) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl BitAnd<Label> for Label {
    type Output = Self;

    #[inline]
    fn bitand(self, rhs: Label) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

impl BitXor<Delta> for Label {
    type Output = Self;

    #[inline]
    fn bitxor(self, rhs: Delta) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl BitAnd<Delta> for Label {
    type Output = Self;

    #[inline]
    fn bitand(self, rhs: Delta) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

impl AsRef<Block> for Label {
    fn as_ref(&self) -> &Block {
        &self.0
    }
}

impl From<Block> for Label {
    fn from(block: Block) -> Self {
        Self(block)
    }
}

impl Label {
    pub const LEN: usize = Block::LEN;

    /// Creates a new label
    #[inline]
    pub fn new(value: Block) -> Self {
        Self(value)
    }

    /// Returns inner block
    #[inline]
    pub fn into_inner(self) -> Block {
        self.0
    }

    /// Returns label permute bit from permute-and-point technique
    #[inline]
    pub fn permute_bit(&self) -> bool {
        self.0.lsb() == 1
    }

    /// Creates a new random label
    #[inline]
    pub fn random<R: Rng + CryptoRng + ?Sized>(rng: &mut R) -> Self {
        Self(Block::random(rng))
    }

    /// Creates label pair from delta and corresponding truth value
    #[inline]
    pub fn to_pair(self, delta: Delta, level: bool) -> LabelPair {
        let (low, high) = if level {
            (self ^ delta, self)
        } else {
            (self, self ^ delta)
        };

        LabelPair(low, high)
    }
}

/// Pair of garbled circuit labels
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LabelPair(Label, Label);

impl LabelPair {
    /// Creates a new label pair
    #[inline]
    pub(crate) fn new(low: Label, high: Label) -> Self {
        Self(low, high)
    }

    /// Returns both labels
    #[inline]
    pub fn to_inner(self) -> [Label; 2] {
        [self.0, self.1]
    }

    /// Returns label corresponding to logical low
    #[inline]
    pub fn low(&self) -> Label {
        self.0
    }

    /// Returns label corresponding to logical high
    #[inline]
    pub fn high(&self) -> Label {
        self.1
    }

    /// Returns label corresponding to provided logic level
    #[inline]
    pub fn select(&self, level: bool) -> Label {
        if level {
            self.1
        } else {
            self.0
        }
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
