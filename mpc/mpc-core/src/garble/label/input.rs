use rand::{CryptoRng, Rng};

use mpc_circuits::{Input, WireGroup};

use crate::{
    garble::{
        label::{state, Delta, Labels, WireLabel},
        LabelError,
    },
    Block,
};

impl Labels<Input, state::Full> {
    /// Generates wire labels for an input group using the provided RNG.
    pub fn generate<R: Rng + CryptoRng>(rng: &mut R, input: Input, delta: Delta) -> Self {
        // Logical low wire labels, [W_0; count]
        let low = Block::random_vec(rng, input.len())
            .into_iter()
            .zip(input.wires())
            .map(|(value, id)| WireLabel { id: *id, value })
            .collect();

        Self {
            group: input,
            state: state::Full::from_labels(low, delta),
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
    impl From<Labels<Input, state::Active>> for UncheckedInputLabels {
        fn from(labels: Labels<Input, state::Active>) -> Self {
            Self {
                id: labels.index(),
                labels: labels.iter_blocks().collect(),
            }
        }
    }

    impl Labels<Input, state::Active> {
        /// Validates and converts input labels to checked variant
        pub fn from_unchecked(
            circ: &Circuit,
            unchecked: UncheckedInputLabels,
        ) -> Result<Self, LabelError> {
            let input = circ
                .input(unchecked.id)
                .map_err(|_| LabelError::InvalidId(circ.id().clone(), unchecked.id))?;

            if unchecked.labels.len() != input.len() {
                return Err(LabelError::InvalidLabelCount(
                    input.id().clone(),
                    input.len(),
                    unchecked.labels.len(),
                ));
            }

            let labels = unchecked
                .labels
                .into_iter()
                .zip(input.wires())
                .map(|(label, id)| WireLabel::new(*id, label))
                .collect();

            Ok(Labels {
                group: input,
                state: state::Active::from_labels(labels),
            })
        }
    }

    #[cfg(test)]
    mod tests {
        use std::sync::Arc;

        use crate::garble::ActiveInputLabels;

        use super::*;
        use rstest::*;

        use mpc_circuits::{Circuit, ADDER_64};

        #[fixture]
        fn circ() -> Arc<Circuit> {
            Circuit::load_bytes(ADDER_64).unwrap()
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
            ActiveInputLabels::from_unchecked(&circ, unchecked_input_labels).unwrap();
        }

        #[rstest]
        fn test_input_labels_wrong_id(
            circ: Arc<Circuit>,
            mut unchecked_input_labels: UncheckedInputLabels,
        ) {
            unchecked_input_labels.id = 10;
            let err = ActiveInputLabels::from_unchecked(&circ, unchecked_input_labels).unwrap_err();
            assert!(matches!(err, LabelError::InvalidId(_, _)))
        }

        #[rstest]
        fn test_input_labels_wrong_count(
            circ: Arc<Circuit>,
            mut unchecked_input_labels: UncheckedInputLabels,
        ) {
            unchecked_input_labels.labels.pop();
            let err = ActiveInputLabels::from_unchecked(&circ, unchecked_input_labels).unwrap_err();
            assert!(matches!(err, LabelError::InvalidLabelCount(_, _, _)))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::garble::label::FullInputLabels;

    use super::*;
    use rstest::*;

    use mpc_circuits::{Circuit, ADDER_64};
    use rand::thread_rng;

    #[fixture]
    pub fn circ() -> Arc<Circuit> {
        Circuit::load_bytes(ADDER_64).unwrap()
    }

    #[rstest]
    fn test_input_label_reconstruction(circ: Arc<Circuit>) {
        let full_labels = FullInputLabels::generate(
            &mut thread_rng(),
            circ.input(0).unwrap(),
            Delta::random(&mut thread_rng()),
        );

        let decoding = full_labels.decoding();

        // select wire labels for value
        let value = circ.input(0).unwrap().to_value(42069u64).unwrap();
        let labels = full_labels.select(&value.value()).unwrap();

        // using delta and value, reconstruct full wire label pairs
        let reconstructed_labels =
            Labels::from_decoding(labels, full_labels.delta(), decoding).unwrap();

        assert_eq!(reconstructed_labels, full_labels);
    }
}
