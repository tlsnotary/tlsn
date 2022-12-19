use rand::{thread_rng, CryptoRng, Rng};
use std::{collections::HashSet, ops::Deref};

use crate::{
    block::Block,
    garble::{Error, InputError},
    utils::sha256,
};
use mpc_circuits::{Circuit, Input, InputValue, Output, OutputValue};
use utils::iter::pick;

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

/// Wire labels corresponding to a circuit input
#[derive(Debug, Clone, PartialEq)]
pub struct InputLabels<T>
where
    T: PartialEq + Copy,
{
    pub input: Input,
    labels: Vec<T>,
}

impl<T> InputLabels<T>
where
    T: PartialEq + Copy,
{
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

    #[cfg(test)]
    /// Returns label at position idx
    ///
    /// Panics if idx is not in range
    pub fn get_label(&self, idx: usize) -> &T {
        &self.labels[idx]
    }

    #[cfg(test)]
    /// Set the value of a wire label at position idx
    pub fn set_label(&mut self, idx: usize, label: T) {
        self.labels[idx] = label;
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
        if self.input.id != value.id() {
            return Err(Error::InvalidInputLabels);
        }

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

    /// Reconstructs input label pairs from existing labels, delta, and value
    pub fn from_input_labels(
        input_labels: InputLabels<WireLabel>,
        delta: Delta,
        value: InputValue,
    ) -> Result<Self, Error> {
        if input_labels.id() != value.id() {
            return Err(Error::InvalidInputLabels);
        }

        let labels: Vec<WireLabelPair> = input_labels
            .labels
            .iter()
            .zip(value.wire_values())
            .map(|(label, value)| label.to_pair(delta, value))
            .collect();

        Ok(InputLabels {
            input: input_labels.input,
            labels,
        })
    }
}

impl<T> AsRef<[T]> for InputLabels<T>
where
    T: PartialEq + Copy,
{
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
    /// Depending on the context, `labels` is a vector of either
    /// - the garbler's **pairs** of output labels or
    /// - the evaluator's active output labels
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

    #[cfg(test)]
    /// Returns label at position idx
    ///
    /// Panics if idx is not in range
    pub fn get_label(&self, idx: usize) -> &T {
        &self.labels[idx]
    }

    #[cfg(test)]
    /// Set the value of a wire label at position idx
    pub fn set_label(&mut self, idx: usize, label: T) {
        self.labels[idx] = label;
    }
}

impl OutputLabels<WireLabelPair> {
    /// Returns output labels decoding info
    pub(crate) fn decoding(&self) -> OutputLabelsDecodingInfo {
        OutputLabelsDecodingInfo::from_labels(self)
    }

    /// Returns commitments for output labels
    pub(crate) fn commit(&self) -> OutputLabelsCommitment {
        OutputLabelsCommitment::new(self)
    }

    /// Returns output wire labels corresponding to an [`OutputValue`]
    pub fn select(&self, value: &OutputValue) -> Result<OutputLabels<WireLabel>, Error> {
        if self.output.id != value.id() {
            return Err(Error::InvalidOutputLabels);
        }

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
    pub(crate) fn decode(&self, decoding: &OutputLabelsDecodingInfo) -> Result<OutputValue, Error> {
        if decoding.output != self.output {
            return Err(Error::InvalidLabelDecodingInfo);
        }
        Ok(self
            .output
            .parse_bits(WireLabel::decode_many(&self.labels, decoding.as_ref())?)?)
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

/// For details about label decoding see [`LabelDecodingInfo`]
#[derive(Debug, Clone, PartialEq)]
pub struct OutputLabelsDecodingInfo {
    pub output: Output,
    decoding: Vec<LabelDecodingInfo>,
}

impl OutputLabelsDecodingInfo {
    fn from_labels(labels: &OutputLabels<WireLabelPair>) -> Self {
        Self {
            output: labels.output.clone(),
            decoding: labels
                .labels
                .iter()
                .map(|label| LabelDecodingInfo(label.low().lsb() == 1))
                .collect::<Vec<LabelDecodingInfo>>(),
        }
    }

    #[cfg(test)]
    pub fn set_decoding(&mut self, idx: usize, value: bool) {
        self.decoding[idx] = LabelDecodingInfo(value);
    }
}

impl AsRef<[LabelDecodingInfo]> for OutputLabelsDecodingInfo {
    fn as_ref(&self) -> &[LabelDecodingInfo] {
        &self.decoding
    }
}

/// Commitments to the output labels of a garbled circuit.
///
/// In some configurations the Generator may send hash commitments to the output labels
/// which the Evaluator can use to detect some types of malicious garbling.
#[derive(Debug, Clone, PartialEq)]
pub struct OutputLabelsCommitment {
    pub(crate) output: Output,
    pub(crate) commitments: Vec<[Block; 2]>,
}

impl OutputLabelsCommitment {
    /// Creates new commitments to output labels
    pub(crate) fn new(output_labels: &OutputLabels<WireLabelPair>) -> Self {
        // randomly shuffle the two labels inside each pair in order to prevent
        // the evaluator from decoding their active output labels
        let mut flip = vec![false; output_labels.labels.len()];
        thread_rng().fill::<[bool]>(&mut flip);

        let output_id = output_labels.id();
        let commitments = output_labels
            .labels
            .iter()
            .zip(&flip)
            .enumerate()
            .map(|(i, (pair, flip))| {
                let low = Self::compute_hash(*pair.low(), output_id, i);
                let high = Self::compute_hash(*pair.high(), output_id, i);
                if *flip {
                    [low, high]
                } else {
                    [high, low]
                }
            })
            .collect();

        Self {
            output: output_labels.output.clone(),
            commitments,
        }
    }

    /// We use a truncated SHA256 hash with a public salt to commit to the labels
    /// H(w || output_id || idx)
    fn compute_hash(block: Block, output_id: usize, idx: usize) -> Block {
        let mut m = [0u8; 32];
        m[..16].copy_from_slice(&block.to_be_bytes());
        m[16..24].copy_from_slice(&(output_id as u64).to_be_bytes());
        m[24..].copy_from_slice(&(idx as u64).to_be_bytes());
        let h = sha256(&m);
        let mut commitment = [0u8; 16];
        commitment.copy_from_slice(&h[..16]);
        commitment.into()
    }

    /// Validates wire labels against commitments
    ///
    /// If this function returns an error the generator may be malicious
    pub(crate) fn validate(&self, output_labels: &OutputLabels<WireLabel>) -> Result<(), Error> {
        if self.commitments.len() != output_labels.labels.len() {
            return Err(Error::InvalidOutputLabelCommitment);
        }
        let output_id = output_labels.id();
        let valid = self
            .commitments
            .iter()
            .zip(&output_labels.labels)
            .enumerate()
            .all(|(i, (pair, label))| {
                let h = Self::compute_hash(label.value, output_id, i);
                h == pair[0] || h == pair[1]
            });

        if valid {
            Ok(())
        } else {
            Err(Error::InvalidOutputLabelCommitment)
        }
    }
}

/// Digest of output wire labels used in [Dual Execution](super::exec::dual) mode
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct OutputCheck(pub(crate) [u8; 32]);

impl OutputCheck {
    /// Creates new output check
    ///
    /// This output check is a hash of the output wire labels from the peer's circuit along with the
    /// expected labels from the callers garbled circuit. The expected labels are determined using
    /// the decoded output values from evaluating the peer's garbled circuit.
    pub fn new(labels: (&[OutputLabels<WireLabel>], &[OutputLabels<WireLabel>])) -> Self {
        let bytes: Vec<u8> = labels
            .0
            .iter()
            .chain(labels.1.iter())
            .map(|labels| labels.to_be_bytes())
            .flatten()
            .collect();
        Self(sha256(&bytes))
    }

    /// Returns check from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Extracts input labels from full set of circuit labels
pub(crate) fn extract_input_labels<T: PartialEq + Copy>(
    circ: &Circuit,
    labels: &[T],
) -> Result<Vec<InputLabels<T>>, Error> {
    circ.inputs()
        .iter()
        .map(|input| {
            InputLabels::new(
                input.clone(),
                &input
                    .as_ref()
                    .wires()
                    .iter()
                    .map(|wire_id| labels[*wire_id])
                    .collect::<Vec<T>>(),
            )
        })
        .collect::<Result<Vec<InputLabels<T>>, Error>>()
}

/// Extracts output labels from full set of circuit labels
pub(crate) fn extract_output_labels<T: Copy>(
    circ: &Circuit,
    labels: &[T],
) -> Result<Vec<OutputLabels<T>>, Error> {
    circ.outputs()
        .iter()
        .map(|output| {
            OutputLabels::new(
                output.clone(),
                &output
                    .as_ref()
                    .wires()
                    .iter()
                    .map(|wire_id| labels[*wire_id])
                    .collect::<Vec<T>>(),
            )
        })
        .collect::<Result<Vec<OutputLabels<T>>, Error>>()
}

/// Decodes evaluated circuit output labels
pub(crate) fn decode_output_labels(
    circ: &Circuit,
    labels: &[OutputLabels<WireLabel>],
    decoding: &[OutputLabelsDecodingInfo],
) -> Result<Vec<OutputValue>, Error> {
    if decoding.len() != circ.output_count() {
        return Err(Error::InvalidLabelDecodingInfo);
    }
    labels
        .iter()
        .zip(decoding.iter())
        .map(|(labels, decoding)| labels.decode(decoding))
        .collect::<Result<Vec<OutputValue>, Error>>()
}

pub(crate) mod unchecked {
    use super::*;

    /// Input labels which have not been validated
    #[derive(Debug, Clone)]
    pub struct UncheckedInputLabels {
        pub(crate) id: usize,
        pub(crate) labels: Vec<Block>,
    }

    #[cfg(test)]
    impl From<InputLabels<WireLabel>> for UncheckedInputLabels {
        fn from(labels: InputLabels<WireLabel>) -> Self {
            Self {
                id: labels.id(),
                labels: labels.labels.into_iter().map(|label| label.value).collect(),
            }
        }
    }

    impl InputLabels<WireLabel> {
        /// Validates and converts input labels to checked variant
        pub fn from_unchecked(
            input: Input,
            unchecked: UncheckedInputLabels,
        ) -> Result<Self, Error> {
            if unchecked.id != input.id || unchecked.labels.len() != input.as_ref().len() {
                return Err(Error::InvalidInputLabels);
            }

            let labels = unchecked
                .labels
                .into_iter()
                .zip(input.as_ref().wires())
                .map(|(label, id)| WireLabel::new(*id, label))
                .collect();

            Ok(Self { input, labels })
        }
    }

    /// Output labels which have not been validated
    #[derive(Debug, Clone)]
    pub struct UncheckedOutputLabels {
        pub(crate) id: usize,
        pub(crate) labels: Vec<Block>,
    }

    #[cfg(test)]
    impl From<OutputLabels<WireLabel>> for UncheckedOutputLabels {
        fn from(labels: OutputLabels<WireLabel>) -> Self {
            Self {
                id: labels.id(),
                labels: labels.labels.into_iter().map(|label| label.value).collect(),
            }
        }
    }

    impl OutputLabels<WireLabel> {
        /// Validates and converts output labels to checked variant
        pub fn from_unchecked(
            output: Output,
            unchecked: UncheckedOutputLabels,
        ) -> Result<Self, Error> {
            if unchecked.id != output.id || unchecked.labels.len() != output.as_ref().len() {
                return Err(Error::InvalidOutputLabels);
            }

            let labels = unchecked
                .labels
                .into_iter()
                .zip(output.as_ref().wires())
                .map(|(label, id)| WireLabel::new(*id, label))
                .collect();

            Ok(Self { output, labels })
        }
    }

    /// Output label decoding info which hasn't been validated against a circuit spec
    ///
    /// For more information on label decoding see [`LabelDecodingInfo`]
    #[derive(Debug, Clone)]
    pub struct UncheckedOutputLabelsDecodingInfo {
        pub(crate) id: usize,
        pub(crate) decoding: Vec<LabelDecodingInfo>,
    }

    #[cfg(test)]
    impl From<OutputLabelsDecodingInfo> for UncheckedOutputLabelsDecodingInfo {
        fn from(decoding: OutputLabelsDecodingInfo) -> Self {
            Self {
                id: decoding.output.id,
                decoding: decoding.decoding,
            }
        }
    }

    impl OutputLabelsDecodingInfo {
        pub fn from_unchecked(
            output: Output,
            unchecked: UncheckedOutputLabelsDecodingInfo,
        ) -> Result<Self, Error> {
            if unchecked.id != output.id || unchecked.decoding.len() != output.as_ref().len() {
                return Err(Error::InvalidLabelDecodingInfo);
            }

            Ok(Self {
                output,
                decoding: unchecked.decoding,
            })
        }
    }

    /// Output label commitments which haven't been validated against a circuit spec
    #[derive(Debug, Clone)]
    pub struct UncheckedOutputLabelsCommitment {
        pub(crate) id: usize,
        pub(crate) commitments: Vec<Block>,
    }

    #[cfg(test)]
    impl From<OutputLabelsCommitment> for UncheckedOutputLabelsCommitment {
        fn from(commitment: OutputLabelsCommitment) -> Self {
            Self {
                id: commitment.output.id,
                commitments: commitment.commitments.into_iter().flatten().collect(),
            }
        }
    }

    impl OutputLabelsCommitment {
        pub(crate) fn from_unchecked(
            output: Output,
            unchecked: UncheckedOutputLabelsCommitment,
        ) -> Result<Self, Error> {
            if unchecked.id != output.id || unchecked.commitments.len() != 2 * output.as_ref().len()
            {
                return Err(Error::ValidationError(
                    "Invalid output labels commitment".to_string(),
                ));
            }

            Ok(Self {
                output,
                commitments: unchecked
                    .commitments
                    .chunks_exact(2)
                    .map(|commitments| [commitments[0], commitments[1]])
                    .collect(),
            })
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use rstest::*;

        use mpc_circuits::{Circuit, ADDER_64};

        #[fixture]
        fn circ() -> Circuit {
            Circuit::load_bytes(ADDER_64).unwrap()
        }

        #[fixture]
        fn input(circ: Circuit) -> Input {
            circ.input(0).unwrap()
        }

        #[fixture]
        fn output(circ: Circuit) -> Output {
            circ.output(0).unwrap()
        }

        #[fixture]
        fn unchecked_input_labels(input: Input) -> UncheckedInputLabels {
            UncheckedInputLabels {
                id: input.id,
                labels: vec![Block::new(0); input.as_ref().len()],
            }
        }

        #[fixture]
        fn unchecked_output_labels(output: Output) -> UncheckedOutputLabels {
            UncheckedOutputLabels {
                id: output.id,
                labels: vec![Block::new(0); output.as_ref().len()],
            }
        }

        #[fixture]
        fn unchecked_output_labels_decoding_info(
            output: Output,
        ) -> UncheckedOutputLabelsDecodingInfo {
            UncheckedOutputLabelsDecodingInfo {
                id: output.id,
                decoding: vec![LabelDecodingInfo(false); output.as_ref().len()],
            }
        }

        #[fixture]
        fn unchecked_output_labels_commitment(output: Output) -> UncheckedOutputLabelsCommitment {
            UncheckedOutputLabelsCommitment {
                id: output.id,
                commitments: vec![Block::new(0); 2 * output.as_ref().len()],
            }
        }

        #[rstest]
        fn test_input_labels(input: Input, unchecked_input_labels: UncheckedInputLabels) {
            InputLabels::from_unchecked(input, unchecked_input_labels).unwrap();
        }

        #[rstest]
        fn test_input_labels_wrong_id(
            input: Input,
            mut unchecked_input_labels: UncheckedInputLabels,
        ) {
            unchecked_input_labels.id += 1;
            let err = InputLabels::from_unchecked(input, unchecked_input_labels).unwrap_err();
            assert!(matches!(err, Error::InvalidInputLabels))
        }

        #[rstest]
        fn test_input_labels_wrong_count(
            input: Input,
            mut unchecked_input_labels: UncheckedInputLabels,
        ) {
            unchecked_input_labels.labels.pop();
            let err = InputLabels::from_unchecked(input, unchecked_input_labels).unwrap_err();
            assert!(matches!(err, Error::InvalidInputLabels))
        }

        #[rstest]
        fn test_output_labels(output: Output, unchecked_output_labels: UncheckedOutputLabels) {
            OutputLabels::from_unchecked(output, unchecked_output_labels).unwrap();
        }

        #[rstest]
        fn test_output_labels_wrong_id(
            output: Output,
            mut unchecked_output_labels: UncheckedOutputLabels,
        ) {
            unchecked_output_labels.id += 1;
            let err = OutputLabels::from_unchecked(output, unchecked_output_labels).unwrap_err();
            assert!(matches!(err, Error::InvalidOutputLabels))
        }

        #[rstest]
        fn test_output_labels_wrong_count(
            output: Output,
            mut unchecked_output_labels: UncheckedOutputLabels,
        ) {
            unchecked_output_labels.labels.pop();
            let err = OutputLabels::from_unchecked(output, unchecked_output_labels).unwrap_err();
            assert!(matches!(err, Error::InvalidOutputLabels))
        }

        #[rstest]
        fn test_output_labels_decoding_info(
            output: Output,
            unchecked_output_labels_decoding_info: UncheckedOutputLabelsDecodingInfo,
        ) {
            OutputLabelsDecodingInfo::from_unchecked(output, unchecked_output_labels_decoding_info)
                .unwrap();
        }

        #[rstest]
        fn test_output_labels_decoding_info_wrong_id(
            output: Output,
            mut unchecked_output_labels_decoding_info: UncheckedOutputLabelsDecodingInfo,
        ) {
            unchecked_output_labels_decoding_info.id += 1;
            let err = OutputLabelsDecodingInfo::from_unchecked(
                output,
                unchecked_output_labels_decoding_info,
            )
            .unwrap_err();
            assert!(matches!(err, Error::InvalidLabelDecodingInfo))
        }

        #[rstest]
        fn test_output_labels_decoding_info_wrong_count(
            output: Output,
            mut unchecked_output_labels_decoding_info: UncheckedOutputLabelsDecodingInfo,
        ) {
            unchecked_output_labels_decoding_info.decoding.pop();
            let err = OutputLabelsDecodingInfo::from_unchecked(
                output,
                unchecked_output_labels_decoding_info,
            )
            .unwrap_err();
            assert!(matches!(err, Error::InvalidLabelDecodingInfo))
        }

        #[rstest]
        fn test_output_labels_commitment(
            output: Output,
            unchecked_output_labels_commitment: UncheckedOutputLabelsCommitment,
        ) {
            OutputLabelsCommitment::from_unchecked(output, unchecked_output_labels_commitment)
                .unwrap();
        }

        #[rstest]
        fn test_output_labels_commitment_wrong_id(
            output: Output,
            mut unchecked_output_labels_commitment: UncheckedOutputLabelsCommitment,
        ) {
            unchecked_output_labels_commitment.id += 1;
            let err =
                OutputLabelsCommitment::from_unchecked(output, unchecked_output_labels_commitment)
                    .unwrap_err();
            assert!(matches!(err, Error::ValidationError(_)))
        }

        #[rstest]
        fn test_output_labels_commitment_wrong_count(
            output: Output,
            mut unchecked_output_labels_commitment: UncheckedOutputLabelsCommitment,
        ) {
            unchecked_output_labels_commitment.commitments.pop();
            let err =
                OutputLabelsCommitment::from_unchecked(output, unchecked_output_labels_commitment)
                    .unwrap_err();
            assert!(matches!(err, Error::ValidationError(_)))
        }
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

    #[rstest]
    fn test_output_label_validation(circ: Circuit) {
        let circ_out = circ.output(0).unwrap();
        let (labels, _) = WireLabelPair::generate(&mut thread_rng(), None, 64, 0);
        let output_labels_full = OutputLabels::new(circ_out.clone(), &labels).unwrap();

        let mut output_labels = output_labels_full
            .select(&circ_out.to_value(1u64).unwrap())
            .unwrap();

        output_labels_full
            .validate(&output_labels)
            .expect("output labels should be valid");

        // insert bogus label
        output_labels.labels[0].value = Block::new(0);

        let error = output_labels_full.validate(&output_labels).unwrap_err();

        assert!(matches!(error, Error::InvalidOutputLabels));
    }

    #[rstest]
    fn test_output_label_commitment_validation(circ: Circuit) {
        let circ_out = circ.output(0).unwrap();
        let (labels, _) = WireLabelPair::generate(&mut thread_rng(), None, 64, 0);
        let output_labels_full = OutputLabels::new(circ_out.clone(), &labels).unwrap();
        let mut commitments = OutputLabelsCommitment::new(&output_labels_full);

        let output_labels = output_labels_full
            .select(&circ_out.to_value(1u64).unwrap())
            .unwrap();

        commitments
            .validate(&output_labels)
            .expect("commitments should be valid");

        // insert bogus commitments
        commitments.commitments[0] = [Block::new(0), Block::new(1)];

        let error = commitments.validate(&output_labels).unwrap_err();

        assert!(matches!(error, Error::InvalidOutputLabelCommitment));
    }

    #[rstest]
    fn test_input_label_reconstruction(circ: Circuit) {
        let (mut full_labels, delta) = InputLabels::generate(&mut thread_rng(), &circ, None);

        // grab input 0
        let full_labels = full_labels.remove(0);

        // select wire labels for value
        let value = circ.input(0).unwrap().to_value(42069u64).unwrap();
        let labels = full_labels.select(&value).unwrap();

        // using delta and value, reconstruct full wire label pairs
        let reconstructed_labels = InputLabels::from_input_labels(labels, delta, value).unwrap();

        assert_eq!(reconstructed_labels, full_labels);
    }
}
