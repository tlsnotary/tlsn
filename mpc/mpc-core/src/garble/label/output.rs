use mpc_circuits::{Input, Output, WireGroup};
use rand::{thread_rng, Rng};

use crate::{
    garble::{
        label::{state, Encoded, Labels},
        EncodingError, Error,
    },
    utils::blake3,
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
    pub(crate) fn new(labels: &Encoded<Output, state::Full>) -> Self {
        // randomly shuffle the two labels inside each pair in order to prevent
        // the evaluator from decoding their active output labels
        let mut flip = vec![false; labels.len()];
        thread_rng().fill::<[bool]>(&mut flip);

        let output_id = labels.index();
        let commitments = labels
            .iter()
            .zip(&flip)
            .enumerate()
            .map(|(i, (pair, flip))| {
                let low = Self::compute_hash(pair.low().into_inner(), output_id, i);
                let high = Self::compute_hash(pair.high().into_inner(), output_id, i);
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

    /// We use a truncated Blake3 hash with a public salt to commit to the labels
    /// H(w || output_id || idx)
    fn compute_hash(block: Block, output_id: usize, idx: usize) -> Block {
        let mut m = [0u8; 32];
        m[..16].copy_from_slice(&block.to_be_bytes());
        m[16..24].copy_from_slice(&(output_id as u64).to_be_bytes());
        m[24..].copy_from_slice(&(idx as u64).to_be_bytes());
        let h = blake3(&m);
        let mut commitment = [0u8; 16];
        commitment.copy_from_slice(&h[..16]);
        commitment.into()
    }

    /// Validates wire labels against commitments
    ///
    /// If this function returns an error the generator may be malicious
    pub(crate) fn validate(
        &self,
        labels: &Encoded<Output, state::Active>,
    ) -> Result<(), EncodingError> {
        if self.commitments.len() != labels.len() {
            return Err(EncodingError::InvalidLabelCommitment(
                self.output.id().clone(),
            ));
        }
        let output_idx = labels.index();
        let valid = self
            .commitments
            .iter()
            .zip(labels.iter_blocks())
            .enumerate()
            .all(|(i, (pair, label))| {
                let h = Self::compute_hash(label, output_idx, i);
                h == pair[0] || h == pair[1]
            });

        if valid {
            Ok(())
        } else {
            Err(EncodingError::InvalidLabelCommitment(
                self.output.id().clone(),
            ))
        }
    }
}

impl Encoded<Output, state::Full> {
    /// Creates commitment to output labels
    pub fn commit(&self) -> OutputLabelsCommitment {
        OutputLabelsCommitment::new(self)
    }
}

impl Encoded<Output, state::Active> {
    /// Converts active output labels to input labels.
    ///
    /// This can be used to chain garbled circuits together
    ///
    /// **Note:** This operation clones the underlying label data
    pub fn to_input(self, input: Input) -> Result<Encoded<Input, state::Active>, EncodingError> {
        Encoded::<Input, state::Active>::from_labels(input, self.labels)
    }
}

pub(crate) mod unchecked {
    use mpc_circuits::Circuit;

    use super::*;

    /// Active output labels which have not been validated
    #[derive(Debug, Clone)]
    pub struct UncheckedOutputLabels {
        pub(crate) id: usize,
        pub(crate) labels: Vec<Block>,
    }

    #[cfg(test)]
    impl From<Encoded<Output, state::Active>> for UncheckedOutputLabels {
        fn from(labels: Encoded<Output, state::Active>) -> Self {
            Self {
                id: labels.index(),
                labels: labels.iter_blocks().collect(),
            }
        }
    }

    impl Encoded<Output, state::Active> {
        /// Validates and converts output labels to checked variant
        pub fn from_unchecked(
            circ: &Circuit,
            unchecked: UncheckedOutputLabels,
        ) -> Result<Self, EncodingError> {
            let output = circ
                .output(unchecked.id)
                .map_err(|_| EncodingError::InvalidId(circ.id().clone(), unchecked.id))?;

            Ok(Self::from_labels(
                output,
                Labels::<state::Active>::from_blocks(unchecked.labels),
            )?)
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
                id: commitment.output.index(),
                commitments: commitment.commitments.into_iter().flatten().collect(),
            }
        }
    }

    impl OutputLabelsCommitment {
        pub(crate) fn from_unchecked(
            output: Output,
            unchecked: UncheckedOutputLabelsCommitment,
        ) -> Result<Self, Error> {
            if unchecked.id != output.index() || unchecked.commitments.len() != 2 * output.len() {
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
        use std::sync::Arc;

        use crate::garble::ActiveEncodedOutput;

        use super::*;
        use rstest::*;

        use mpc_circuits::{Circuit, ADDER_64};

        #[fixture]
        fn circ() -> Arc<Circuit> {
            ADDER_64.clone()
        }

        #[fixture]
        fn output(circ: Arc<Circuit>) -> Output {
            circ.output(0).unwrap()
        }

        #[fixture]
        fn unchecked_output_labels(output: Output) -> UncheckedOutputLabels {
            UncheckedOutputLabels {
                id: output.index(),
                labels: vec![Block::new(0); output.len()],
            }
        }

        #[fixture]
        fn unchecked_output_labels_commitment(output: Output) -> UncheckedOutputLabelsCommitment {
            UncheckedOutputLabelsCommitment {
                id: output.index(),
                commitments: vec![Block::new(0); 2 * output.len()],
            }
        }

        #[rstest]
        fn test_output_labels(circ: Arc<Circuit>, unchecked_output_labels: UncheckedOutputLabels) {
            ActiveEncodedOutput::from_unchecked(&circ, unchecked_output_labels).unwrap();
        }

        #[rstest]
        fn test_output_labels_wrong_id(
            circ: Arc<Circuit>,
            mut unchecked_output_labels: UncheckedOutputLabels,
        ) {
            unchecked_output_labels.id += 1;
            let err =
                ActiveEncodedOutput::from_unchecked(&circ, unchecked_output_labels).unwrap_err();
            assert!(matches!(err, EncodingError::InvalidId(_, _)))
        }

        #[rstest]
        fn test_output_labels_wrong_count(
            circ: Arc<Circuit>,
            mut unchecked_output_labels: UncheckedOutputLabels,
        ) {
            unchecked_output_labels.labels.pop();
            let err =
                ActiveEncodedOutput::from_unchecked(&circ, unchecked_output_labels).unwrap_err();
            assert!(matches!(err, EncodingError::InvalidLabelCount(_, _, _)))
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
    use std::sync::Arc;

    use crate::garble::{EncodingError, FullEncodedOutput, Label};

    use super::*;
    use rstest::*;

    use mpc_circuits::{Circuit, ADDER_64, AES_128};
    use rand::thread_rng;

    #[fixture]
    pub fn circ() -> Arc<Circuit> {
        ADDER_64.clone()
    }

    #[rstest]
    fn test_output_label_validation(circ: Arc<Circuit>) {
        let circ_out = circ.output(0).unwrap();
        let labels = Labels::<state::Full>::generate(&mut thread_rng(), 64, None);
        let output_labels_full = FullEncodedOutput::from_labels(circ_out.clone(), labels).unwrap();

        let mut output_labels = output_labels_full.select(&1u64.into()).unwrap();

        output_labels_full
            .validate(&output_labels)
            .expect("output labels should be valid");

        // insert bogus label
        output_labels.labels.set(0, Label::new(Block::new(0)));

        let error = output_labels_full.validate(&output_labels).unwrap_err();

        assert!(matches!(error, EncodingError::InauthenticLabels(_)));
    }

    #[rstest]
    fn test_output_label_commitment_validation(circ: Arc<Circuit>) {
        let circ_out = circ.output(0).unwrap();
        let labels = Labels::<state::Full>::generate(&mut thread_rng(), 64, None);
        let output_labels_full = FullEncodedOutput::from_labels(circ_out.clone(), labels).unwrap();
        let mut commitments = OutputLabelsCommitment::new(&output_labels_full);

        let output_labels = output_labels_full.select(&1u64.into()).unwrap();

        commitments
            .validate(&output_labels)
            .expect("commitments should be valid");

        // insert bogus commitments
        commitments.commitments[0] = [Block::new(0), Block::new(1)];

        let error = commitments.validate(&output_labels).unwrap_err();

        assert!(matches!(error, EncodingError::InvalidLabelCommitment(_)));
    }

    #[rstest]
    fn test_to_input_labels(circ: Arc<Circuit>) {
        let input = circ.input(0).unwrap();
        let output = circ.output(0).unwrap();

        let labels = Labels::<state::Full>::generate(&mut thread_rng(), 64, None);
        let output_labels = FullEncodedOutput::from_labels(output.clone(), labels)
            .unwrap()
            .select(&1u64.into())
            .unwrap();

        _ = output_labels.to_input(input).unwrap();
    }

    #[rstest]
    fn test_to_input_labels_length_mismatch(circ: Arc<Circuit>) {
        let circ_2 = AES_128.clone();

        let input = circ_2.input(0).unwrap();
        let output = circ.output(0).unwrap();

        let labels = Labels::<state::Full>::generate(&mut thread_rng(), 64, None);
        let output_labels = FullEncodedOutput::from_labels(output.clone(), labels)
            .unwrap()
            .select(&1u64.into())
            .unwrap();

        let err = output_labels.to_input(input).unwrap_err();

        assert!(matches!(err, EncodingError::InvalidLabelCount(_, _, _)));
    }
}
