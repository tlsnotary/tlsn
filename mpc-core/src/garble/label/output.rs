use mpc_circuits::{Input, Output, WireGroup};
use rand::{thread_rng, Rng};

use crate::{
    garble::{
        label::{state, Labels, WireLabel},
        Error, LabelError,
    },
    utils::sha256,
    Block,
};

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
    pub(crate) fn new(labels: &Labels<Output, state::Full>) -> Self {
        // randomly shuffle the two labels inside each pair in order to prevent
        // the evaluator from decoding their active output labels
        let mut flip = vec![false; labels.len()];
        thread_rng().fill::<[bool]>(&mut flip);

        let output_id = labels.id();
        let commitments = labels
            .inner()
            .iter()
            .zip(&flip)
            .enumerate()
            .map(|(i, (pair, flip))| {
                let low = Self::compute_hash(pair.low(), output_id, i);
                let high = Self::compute_hash(pair.high(), output_id, i);
                if *flip {
                    [low, high]
                } else {
                    [high, low]
                }
            })
            .collect();

        Self {
            output: labels.group.clone(),
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
    pub(crate) fn validate(
        &self,
        labels: &Labels<Output, state::Active>,
    ) -> Result<(), LabelError> {
        if self.commitments.len() != labels.len() {
            return Err(LabelError::InvalidLabelCommitment(
                self.output.name().to_string(),
            ));
        }
        let output_id = labels.id();
        let valid = self
            .commitments
            .iter()
            .zip(labels.iter_blocks())
            .enumerate()
            .all(|(i, (pair, label))| {
                let h = Self::compute_hash(label, output_id, i);
                h == pair[0] || h == pair[1]
            });

        if valid {
            Ok(())
        } else {
            Err(LabelError::InvalidLabelCommitment(
                self.output.name().to_string(),
            ))
        }
    }
}

impl Labels<Output, state::Full> {
    /// Creates commitment to output labels
    pub fn commit(&self) -> OutputLabelsCommitment {
        OutputLabelsCommitment::new(self)
    }
}

impl Labels<Output, state::Active> {
    /// Converts active output labels to input labels.
    ///
    /// This can be used to chain garbled circuits together
    ///
    /// **Note:** This operation clones the underlying label data
    pub fn to_input(self, input: Input) -> Result<Labels<Input, state::Active>, LabelError> {
        Labels::<Input, state::Active>::from_labels(input, self.iter().collect())
    }
}

pub(crate) mod unchecked {
    use super::*;

    /// Active output labels which have not been validated
    #[derive(Debug, Clone)]
    pub struct UncheckedOutputLabels {
        pub(crate) id: usize,
        pub(crate) labels: Vec<Block>,
    }

    #[cfg(test)]
    impl From<Labels<Output, state::Active>> for UncheckedOutputLabels {
        fn from(labels: Labels<Output, state::Active>) -> Self {
            Self {
                id: labels.id(),
                labels: labels.iter_blocks().collect(),
            }
        }
    }

    impl Labels<Output, state::Active> {
        /// Validates and converts output labels to checked variant
        pub fn from_unchecked(
            output: Output,
            unchecked: UncheckedOutputLabels,
        ) -> Result<Self, LabelError> {
            if unchecked.id != output.id() {
                return Err(LabelError::InvalidLabelId(
                    output.name().to_string(),
                    output.id(),
                    unchecked.id,
                ));
            } else if unchecked.labels.len() != output.len() {
                return Err(LabelError::InvalidLabelCount(
                    output.name().to_string(),
                    output.len(),
                    unchecked.labels.len(),
                ));
            }

            let labels = unchecked
                .labels
                .into_iter()
                .zip(output.wires())
                .map(|(label, id)| WireLabel::new(*id, label))
                .collect();

            Ok(Self::from_labels(output, labels)?)
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
            if unchecked.id != output.id() || unchecked.commitments.len() != 2 * output.len() {
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
        use crate::garble::ActiveOutputLabels;

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
                labels: vec![Block::new(0); output.len()],
            }
        }

        #[fixture]
        fn unchecked_output_labels_commitment(output: Output) -> UncheckedOutputLabelsCommitment {
            UncheckedOutputLabelsCommitment {
                id: output.id(),
                commitments: vec![Block::new(0); 2 * output.len()],
            }
        }

        #[rstest]
        fn test_output_labels(output: Output, unchecked_output_labels: UncheckedOutputLabels) {
            ActiveOutputLabels::from_unchecked(output, unchecked_output_labels).unwrap();
        }

        #[rstest]
        fn test_output_labels_wrong_id(
            output: Output,
            mut unchecked_output_labels: UncheckedOutputLabels,
        ) {
            unchecked_output_labels.id += 1;
            let err =
                ActiveOutputLabels::from_unchecked(output, unchecked_output_labels).unwrap_err();
            assert!(matches!(err, LabelError::InvalidLabelId(_, _, _)))
        }

        #[rstest]
        fn test_output_labels_wrong_count(
            output: Output,
            mut unchecked_output_labels: UncheckedOutputLabels,
        ) {
            unchecked_output_labels.labels.pop();
            let err =
                ActiveOutputLabels::from_unchecked(output, unchecked_output_labels).unwrap_err();
            assert!(matches!(err, LabelError::InvalidLabelCount(_, _, _)))
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
    use crate::garble::{FullOutputLabels, LabelError, WireLabelPair};

    use super::*;
    use rstest::*;

    use mpc_circuits::{Circuit, ADDER_64, AES_128_REVERSE};
    use rand::thread_rng;

    #[fixture]
    pub fn circ() -> Circuit {
        Circuit::load_bytes(ADDER_64).unwrap()
    }

    #[rstest]
    fn test_output_label_validation(circ: Circuit) {
        let circ_out = circ.output(0).unwrap();
        let (labels, delta) = WireLabelPair::generate(&mut thread_rng(), None, 64, 0);
        let output_labels_full =
            FullOutputLabels::from_labels(circ_out.clone(), delta, labels).unwrap();

        let mut output_labels = output_labels_full.select(&1u64.into()).unwrap();

        output_labels_full
            .validate(&output_labels)
            .expect("output labels should be valid");

        // insert bogus label
        output_labels.state.set(0, WireLabel::new(0, Block::new(0)));

        let error = output_labels_full.validate(&output_labels).unwrap_err();

        assert!(matches!(error, LabelError::InauthenticLabels(_)));
    }

    #[rstest]
    fn test_output_label_commitment_validation(circ: Circuit) {
        let circ_out = circ.output(0).unwrap();
        let (labels, delta) = WireLabelPair::generate(&mut thread_rng(), None, 64, 0);
        let output_labels_full =
            FullOutputLabels::from_labels(circ_out.clone(), delta, labels).unwrap();
        let mut commitments = OutputLabelsCommitment::new(&output_labels_full);

        let output_labels = output_labels_full.select(&1u64.into()).unwrap();

        commitments
            .validate(&output_labels)
            .expect("commitments should be valid");

        // insert bogus commitments
        commitments.commitments[0] = [Block::new(0), Block::new(1)];

        let error = commitments.validate(&output_labels).unwrap_err();

        assert!(matches!(error, LabelError::InvalidLabelCommitment(_)));
    }

    #[rstest]
    fn test_to_input_labels(circ: Circuit) {
        let input = circ.input(0).unwrap();
        let output = circ.output(0).unwrap();

        let (labels, delta) = WireLabelPair::generate(&mut thread_rng(), None, 64, 0);
        let output_labels = FullOutputLabels::from_labels(output, delta, labels)
            .unwrap()
            .select(&1u64.into())
            .unwrap();

        _ = output_labels.to_input(input).unwrap();
    }

    #[rstest]
    fn test_to_input_labels_length_mismatch(circ: Circuit) {
        let circ_2 = Circuit::load_bytes(AES_128_REVERSE).unwrap();

        let input = circ_2.input(0).unwrap();
        let output = circ.output(0).unwrap();

        let (labels, delta) = WireLabelPair::generate(&mut thread_rng(), None, 64, 0);
        let output_labels = FullOutputLabels::from_labels(output, delta, labels)
            .unwrap()
            .select(&1u64.into())
            .unwrap();

        let err = output_labels.to_input(input).unwrap_err();

        assert!(matches!(err, LabelError::InvalidLabelCount(_, _, _)));
    }
}
