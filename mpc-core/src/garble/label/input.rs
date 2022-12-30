use rand::{CryptoRng, Rng};
use std::collections::HashSet;
use utils::iter::pick;

use mpc_circuits::{Circuit, Input, InputValue, WireGroup};

use crate::{
    garble::{
        label::{Delta, LabelDecodingInfo, WireLabel, WireLabelPair},
        Error, InputError,
    },
    Block,
};

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

    /// Returns input id
    pub fn id(&self) -> usize {
        self.input.id()
    }

    /// Returns labels
    pub(crate) fn to_inner(self) -> Vec<T> {
        self.labels
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
    /// Returns input labels in block representation
    pub fn to_blocks(self) -> Vec<[Block; 2]> {
        self.labels
            .into_iter()
            .map(|labels| labels.to_inner())
            .collect()
    }

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
        if self.input.id() != value.id() {
            return Err(Error::InvalidInputLabels);
        }

        let labels: Vec<WireLabel> = self
            .labels
            .iter()
            .zip(value.value().to_bits())
            .map(|(pair, value)| pair.select(value))
            .collect();

        Ok(InputLabels {
            input: self.input.clone(),
            labels,
        })
    }

    /// Returns input label decoding info
    pub fn decoding(&self) -> InputLabelsDecodingInfo {
        InputLabelsDecodingInfo {
            input: self.input.clone(),
            decoding: self
                .labels
                .iter()
                .map(|label| LabelDecodingInfo(label.low().lsb() == 1))
                .collect(),
        }
    }

    /// Reconstructs input label pairs from existing labels, delta, and decoding info
    pub fn from_decoding(
        input_labels: InputLabels<WireLabel>,
        delta: Delta,
        decoding: InputLabelsDecodingInfo,
    ) -> Result<Self, Error> {
        if input_labels.id() != decoding.input.id() {
            return Err(Error::InvalidLabelDecodingInfo);
        }

        let labels: Vec<WireLabelPair> = input_labels
            .labels
            .iter()
            .zip(decoding.decoding)
            .map(|(label, decoding)| label.to_pair(delta, label.decode(decoding)))
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

/// For details about label decoding see [`LabelDecodingInfo`]
#[derive(Debug, Clone, PartialEq)]
pub struct InputLabelsDecodingInfo {
    pub input: Input,
    decoding: Vec<LabelDecodingInfo>,
}

impl AsRef<[LabelDecodingInfo]> for InputLabelsDecodingInfo {
    fn as_ref(&self) -> &[LabelDecodingInfo] {
        &self.decoding
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
            if unchecked.id != input.id() || unchecked.labels.len() != input.as_ref().len() {
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

    /// Input label decoding info which hasn't been validated against a circuit spec
    ///
    /// For more information on label decoding see [`LabelDecodingInfo`]
    #[derive(Debug, Clone)]
    pub struct UncheckedInputLabelsDecodingInfo {
        /// the id of the circuit [Input] which this decoding info is for
        pub(crate) id: usize,
        pub(crate) decoding: Vec<LabelDecodingInfo>,
    }

    #[cfg(test)]
    impl From<InputLabelsDecodingInfo> for UncheckedInputLabelsDecodingInfo {
        fn from(decoding: InputLabelsDecodingInfo) -> Self {
            Self {
                id: decoding.input.id(),
                decoding: decoding.decoding,
            }
        }
    }

    impl InputLabelsDecodingInfo {
        pub fn from_unchecked(
            input: Input,
            unchecked: unchecked::UncheckedInputLabelsDecodingInfo,
        ) -> Result<Self, Error> {
            if unchecked.id != input.id() || unchecked.decoding.len() != input.as_ref().len() {
                return Err(Error::InvalidLabelDecodingInfo);
            }

            Ok(Self {
                input,
                decoding: unchecked.decoding,
            })
        }

        #[cfg(test)]
        pub fn set_decoding(&mut self, idx: usize, value: bool) {
            self.decoding[idx] = LabelDecodingInfo(value);
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
        fn unchecked_input_labels(input: Input) -> UncheckedInputLabels {
            UncheckedInputLabels {
                id: input.id(),
                labels: vec![Block::new(0); input.as_ref().len()],
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
    fn test_input_label_reconstruction(circ: Circuit) {
        let (mut full_labels, delta) = InputLabels::generate(&mut thread_rng(), &circ, None);

        // grab input 0
        let full_labels = full_labels.remove(0);
        let decoding = full_labels.decoding();

        // select wire labels for value
        let value = circ.input(0).unwrap().to_value(42069u64).unwrap();
        let labels = full_labels.select(&value).unwrap();

        // using delta and value, reconstruct full wire label pairs
        let reconstructed_labels = InputLabels::from_decoding(labels, delta, decoding).unwrap();

        assert_eq!(reconstructed_labels, full_labels);
    }
}
