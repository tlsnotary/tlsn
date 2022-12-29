use mpc_circuits::{Circuit, Output, OutputValue, WireGroup};
use rand::{thread_rng, Rng};

use crate::{
    garble::{
        label::{LabelDecodingInfo, WireLabel, WireLabelPair},
        Error,
    },
    utils::sha256,
    Block,
};

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
        if output.len() != labels.len() {
            return Err(Error::InvalidOutputLabels);
        }

        Ok(Self {
            output,
            labels: labels.to_vec(),
        })
    }

    pub fn id(&self) -> usize {
        self.output.id()
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
        if self.output.id() != value.id() {
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
            if unchecked.id != output.id() || unchecked.labels.len() != output.as_ref().len() {
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
                id: decoding.output.id(),
                decoding: decoding.decoding,
            }
        }
    }

    impl OutputLabelsDecodingInfo {
        pub fn from_unchecked(
            output: Output,
            unchecked: UncheckedOutputLabelsDecodingInfo,
        ) -> Result<Self, Error> {
            if unchecked.id != output.id() || unchecked.decoding.len() != output.as_ref().len() {
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
                id: commitment.output.id(),
                commitments: commitment.commitments.into_iter().flatten().collect(),
            }
        }
    }

    impl OutputLabelsCommitment {
        pub(crate) fn from_unchecked(
            output: Output,
            unchecked: UncheckedOutputLabelsCommitment,
        ) -> Result<Self, Error> {
            if unchecked.id != output.id()
                || unchecked.commitments.len() != 2 * output.as_ref().len()
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
        fn output(circ: Circuit) -> Output {
            circ.output(0).unwrap()
        }

        #[fixture]
        fn unchecked_output_labels(output: Output) -> UncheckedOutputLabels {
            UncheckedOutputLabels {
                id: output.id(),
                labels: vec![Block::new(0); output.as_ref().len()],
            }
        }

        #[fixture]
        fn unchecked_output_labels_decoding_info(
            output: Output,
        ) -> UncheckedOutputLabelsDecodingInfo {
            UncheckedOutputLabelsDecodingInfo {
                id: output.id(),
                decoding: vec![LabelDecodingInfo(false); output.as_ref().len()],
            }
        }

        #[fixture]
        fn unchecked_output_labels_commitment(output: Output) -> UncheckedOutputLabelsCommitment {
            UncheckedOutputLabelsCommitment {
                id: output.id(),
                commitments: vec![Block::new(0); 2 * output.as_ref().len()],
            }
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
}
