use rand::{CryptoRng, Rng};

use mpc_circuits::{Input, WireGroup};

use crate::{
    garble::{
        label::{state, Delta, Encoded, Labels},
        EncodingError,
    },
    Block,
};

impl Encoded<Input, state::Full> {
    /// Generates wire labels for an input group using the provided RNG.
    pub fn generate<R: Rng + CryptoRng + ?Sized>(rng: &mut R, input: Input, delta: Delta) -> Self {
        let labels = Labels::generate(rng, input.len(), Some(delta));

        Self {
            group: input,
            labels,
        }
    }
}

pub(crate) mod unchecked {
    use mpc_circuits::Circuit;

    use super::*;

    /// Input labels which have not been validated
    #[derive(Debug, Clone)]
    pub struct UncheckedInputLabels {
        pub(crate) id: usize,
        pub(crate) labels: Vec<Block>,
    }

    #[cfg(test)]
    impl From<Encoded<Input, state::Active>> for UncheckedInputLabels {
        fn from(labels: Encoded<Input, state::Active>) -> Self {
            Self {
                id: labels.index(),
                labels: labels.iter_blocks().collect(),
            }
        }
    }

    impl Encoded<Input, state::Active> {
        /// Validates and converts input labels to checked variant
        pub fn from_unchecked(
            circ: &Circuit,
            unchecked: UncheckedInputLabels,
        ) -> Result<Self, EncodingError> {
            let input = circ
                .input(unchecked.id)
                .map_err(|_| EncodingError::InvalidId(circ.id().clone(), unchecked.id))?;

            if unchecked.labels.len() != input.len() {
                return Err(EncodingError::InvalidLabelCount(
                    input.id().clone(),
                    input.len(),
                    unchecked.labels.len(),
                ));
            }

            Ok(Encoded {
                group: input,
                labels: Labels::<state::Active>::from_blocks(unchecked.labels),
            })
        }
    }

    #[cfg(test)]
    mod tests {
        use std::sync::Arc;

        use crate::garble::ActiveEncodedInput;

        use super::*;
        use rstest::*;

        use mpc_circuits::{Circuit, ADDER_64};

        #[fixture]
        fn circ() -> Arc<Circuit> {
            ADDER_64.clone()
        }

        #[fixture]
        fn input(circ: Arc<Circuit>) -> Input {
            circ.input(0).unwrap()
        }

        #[fixture]
        fn unchecked_input_labels(input: Input) -> UncheckedInputLabels {
            UncheckedInputLabels {
                id: input.index(),
                labels: vec![Block::new(0); input.as_ref().len()],
            }
        }

        #[rstest]
        fn test_input_labels(circ: Arc<Circuit>, unchecked_input_labels: UncheckedInputLabels) {
            ActiveEncodedInput::from_unchecked(&circ, unchecked_input_labels).unwrap();
        }

        #[rstest]
        fn test_input_labels_wrong_id(
            circ: Arc<Circuit>,
            mut unchecked_input_labels: UncheckedInputLabels,
        ) {
            unchecked_input_labels.id = 10;
            let err =
                ActiveEncodedInput::from_unchecked(&circ, unchecked_input_labels).unwrap_err();
            assert!(matches!(err, EncodingError::InvalidId(_, _)))
        }

        #[rstest]
        fn test_input_labels_wrong_count(
            circ: Arc<Circuit>,
            mut unchecked_input_labels: UncheckedInputLabels,
        ) {
            unchecked_input_labels.labels.pop();
            let err =
                ActiveEncodedInput::from_unchecked(&circ, unchecked_input_labels).unwrap_err();
            assert!(matches!(err, EncodingError::InvalidLabelCount(_, _, _)))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::garble::label::FullEncodedInput;

    use super::*;
    use rstest::*;

    use mpc_circuits::{Circuit, ADDER_64};
    use rand::thread_rng;

    #[fixture]
    pub fn circ() -> Arc<Circuit> {
        ADDER_64.clone()
    }

    #[rstest]
    fn test_input_label_reconstruction(circ: Arc<Circuit>) {
        let full_labels = FullEncodedInput::generate(
            &mut thread_rng(),
            circ.input(0).unwrap(),
            Delta::random(&mut thread_rng()),
        );

        let decoding = full_labels.get_decoding();

        // select wire labels for value
        let value = circ.input(0).unwrap().to_value(42069u64).unwrap();
        let labels = full_labels.select(&value.value()).unwrap();

        // using delta and value, reconstruct full wire label pairs
        let reconstructed_labels =
            Encoded::from_decoding(labels, full_labels.delta(), decoding).unwrap();

        assert_eq!(reconstructed_labels, full_labels);
    }
}
