pub(crate) mod input;
pub(crate) mod output;

use rand::{CryptoRng, Rng};
use std::ops::Deref;

use crate::{block::Block, garble::Error};

pub(crate) use input::extract_input_labels;
pub use input::{InputLabels, InputLabelsDecodingInfo, SanitizedInputLabels};
pub(crate) use output::{decode_output_labels, extract_output_labels};
pub use output::{OutputCheck, OutputLabels, OutputLabelsCommitment, OutputLabelsDecodingInfo};

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

impl From<[u8; 16]> for Delta {
    #[inline]
    fn from(bytes: [u8; 16]) -> Self {
        Self(Block::from(bytes))
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
    pub fn decode(&self, decoding: LabelDecodingInfo) -> bool {
        self.permute_bit() ^ *decoding
    }

    /// Decodes output wire labels into plaintext.
    ///
    /// Thanks to the permute-and-point (p&p) technique, the two adjacent labels
    /// will have the opposite p&p bits. We apply the decoding to the p&p bits.
    pub fn decode_many(
        labels: &[Self],
        decoding: &[LabelDecodingInfo],
    ) -> Result<Vec<bool>, Error> {
        if labels.len() != decoding.len() {
            return Err(Error::InvalidLabelDecodingInfo);
        }
        Ok(labels
            .iter()
            .zip(decoding)
            .map(|(label, decoding)| label.decode(*decoding))
            .collect())
    }

    /// Creates a new random wire label
    pub fn random<R: Rng + CryptoRng>(id: usize, rng: &mut R) -> Self {
        Self {
            id,
            value: Block::random(rng),
        }
    }

    /// Creates wire label pair from delta and corresponding truth value
    #[inline]
    pub fn to_pair(self, delta: Delta, level: bool) -> WireLabelPair {
        let (low, high) = if level {
            (self.value ^ delta.0, self.value)
        } else {
            (self.value, self.value ^ delta.0)
        };

        WireLabelPair {
            id: self.id,
            low,
            high,
        }
    }
}

/// Pair of garbled circuit wire labels
#[derive(Debug, Clone, Copy, PartialEq)]
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

/// Decoding info for a garbled circuit wire label.
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
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LabelDecodingInfo(bool);

impl From<bool> for LabelDecodingInfo {
    #[inline]
    fn from(value: bool) -> Self {
        Self(value)
    }
}

impl Deref for LabelDecodingInfo {
    type Target = bool;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
