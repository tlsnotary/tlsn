use rand::{CryptoRng, Rng};
use std::collections::HashSet;

use mpc_circuits::{Circuit, Input, WireGroup};

use crate::{
    garble::{
        label::{state, Delta, Labels, WireLabel},
        Error, InputError, LabelError,
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

    /// Generates a full set of input wire labels for a circuit using the provided RNG.
    pub fn generate_set<R: Rng + CryptoRng>(
        rng: &mut R,
        circ: &Circuit,
        delta: Option<Delta>,
    ) -> (Vec<Self>, Delta) {
        let delta = delta.unwrap_or_else(|| Delta::random(rng));
        (
            circ.inputs()
                .iter()
                .map(|input| Self::generate(rng, input.clone(), delta))
                .collect(),
            delta,
        )
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
        gen_labels: &[Labels<Input, state::Active>],
        ev_labels: &[Labels<Input, state::Active>],
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
            .map(|labels| labels.iter().collect::<Vec<WireLabel>>())
            .flatten()
            .collect();

        labels.sort_by_key(|label| label.id());
        let label_count = labels.len();
        labels.dedup_by_key(|label| label.id());

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

pub(crate) mod unchecked {
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
                id: labels.id(),
                labels: labels.iter_blocks().collect(),
            }
        }
    }

    impl Labels<Input, state::Active> {
        /// Validates and converts input labels to checked variant
        pub fn from_unchecked(
            input: Input,
            unchecked: UncheckedInputLabels,
        ) -> Result<Self, LabelError> {
            if unchecked.id != input.id() {
                return Err(LabelError::InvalidLabelId(
                    input.name().to_string(),
                    input.id(),
                    unchecked.id,
                ));
            } else if unchecked.labels.len() != input.len() {
                return Err(LabelError::InvalidLabelCount(
                    input.name().to_string(),
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
                id: input.id(),
                labels: vec![Block::new(0); input.as_ref().len()],
            }
        }

        #[rstest]
        fn test_input_labels(input: Input, unchecked_input_labels: UncheckedInputLabels) {
            ActiveInputLabels::from_unchecked(input, unchecked_input_labels).unwrap();
        }

        #[rstest]
        fn test_input_labels_wrong_id(
            input: Input,
            mut unchecked_input_labels: UncheckedInputLabels,
        ) {
            unchecked_input_labels.id += 1;
            let err = ActiveInputLabels::from_unchecked(input, unchecked_input_labels).unwrap_err();
            assert!(matches!(err, LabelError::InvalidLabelId(_, _, _)))
        }

        #[rstest]
        fn test_input_labels_wrong_count(
            input: Input,
            mut unchecked_input_labels: UncheckedInputLabels,
        ) {
            unchecked_input_labels.labels.pop();
            let err = ActiveInputLabels::from_unchecked(input, unchecked_input_labels).unwrap_err();
            assert!(matches!(err, LabelError::InvalidLabelCount(_, _, _)))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use rstest::*;

    use mpc_circuits::{Circuit, Value, ADDER_64};
    use rand::thread_rng;

    #[fixture]
    pub fn circ() -> Arc<Circuit> {
        Circuit::load_bytes(ADDER_64).unwrap()
    }

    #[rstest]
    fn test_sanitized_labels_dup(circ: Arc<Circuit>) {
        let (labels, _) = Labels::generate_set(&mut thread_rng(), &circ, None);
        let input_values = [Value::from(0u64), Value::from(0u64)];

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
    fn test_sanitized_labels_wrong_count(circ: Arc<Circuit>) {
        let (labels, _) = Labels::generate_set(&mut thread_rng(), &circ, None);
        let input_values = [Value::from(0u64), Value::from(0u64)];

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
    fn test_sanitized_labels_duplicate_wires(circ: Arc<Circuit>) {
        let (labels, _) = Labels::generate_set(&mut thread_rng(), &circ, None);
        let input_values = [Value::from(0u64), Value::from(0u64)];

        let mut input_labels = [
            labels[0].clone().select(&input_values[0]).unwrap(),
            labels[1].clone().select(&input_values[1]).unwrap(),
        ];

        // Somehow manages to get an overlapping label id here
        input_labels[1].set(0, WireLabel::new(0, Block::new(0)));

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
            .state
            .push(WireLabel::new(0, crate::Block::new(0)));

        let gen_labels = [input_labels[1].clone()];
        let ev_labels = [input_labels[0].clone()];

        assert!(matches!(
            SanitizedInputLabels::new(&circ, &gen_labels, &ev_labels),
            Err(Error::InvalidInput(InputError::Duplicate))
        ));
    }

    #[rstest]
    fn test_sanitized_labels_invalid_wire_count(circ: Arc<Circuit>) {
        let (labels, _) = Labels::generate_set(&mut thread_rng(), &circ, None);
        let input_values = [Value::from(0u64), Value::from(0u64)];

        let mut input_labels = [
            labels[0].clone().select(&input_values[0]).unwrap(),
            labels[1].clone().select(&input_values[1]).unwrap(),
        ];

        // Somehow manages to get an input missing a wire label here
        input_labels[1].state.pop();

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
            .state
            .push(WireLabel::new(usize::MAX, crate::Block::new(0)));

        let gen_labels = [input_labels[1].clone()];
        let ev_labels = [input_labels[0].clone()];

        assert!(matches!(
            SanitizedInputLabels::new(&circ, &gen_labels, &ev_labels),
            Err(Error::InvalidInput(InputError::InvalidWireCount(_, _)))
        ));
    }

    #[rstest]
    fn test_input_label_reconstruction(circ: Arc<Circuit>) {
        let (mut full_labels, delta) = Labels::generate_set(&mut thread_rng(), &circ, None);

        // grab input 0
        let full_labels = full_labels.remove(0);
        let decoding = full_labels.decoding();

        // select wire labels for value
        let value = circ.input(0).unwrap().to_value(42069u64).unwrap();
        let labels = full_labels.select(&value.value()).unwrap();

        // using delta and value, reconstruct full wire label pairs
        let reconstructed_labels = Labels::from_decoding(labels, delta, decoding).unwrap();

        assert_eq!(reconstructed_labels, full_labels);
    }
}
