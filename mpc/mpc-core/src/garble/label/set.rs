use std::{ops::Index, sync::Arc};

use mpc_circuits::{Circuit, Input, Output, WireGroup};
use rand::{CryptoRng, Rng};
use utils::iter::DuplicateCheckBy;

use crate::garble::LabelError;

use super::{
    state::{Active, Full, State},
    Delta, FullInputLabels, Labels,
};

/// A complete set of circuit labels
#[derive(Debug, Clone)]
pub struct LabelsSet<G, S>
where
    G: WireGroup + Clone,
    S: State,
{
    labels: Vec<Labels<G, S>>,
}

impl<G, S> LabelsSet<G, S>
where
    G: WireGroup + Clone,
    S: State,
{
    /// Returns the circuit the set belongs to
    pub fn circuit(&self) -> Arc<Circuit> {
        self.labels[0].circuit()
    }

    /// Returns a reference to the labels in the set
    pub fn get_labels(&self) -> &[Labels<G, S>] {
        &self.labels
    }

    /// Consumes set, returning all labels in the set
    pub fn to_inner(self) -> Vec<Labels<G, S>> {
        self.labels
    }

    /// Returns a reference to the labels at that index or `None` if it is not part
    /// of the set.
    pub fn get(&self, index: usize) -> Option<&Labels<G, S>> {
        self.labels.get(index)
    }

    /// Returns an iterator of the labels in the set
    pub fn iter(&self) -> impl Iterator<Item = &Labels<G, S>> {
        self.labels.iter()
    }

    fn generic_checks(labels: &[Labels<G, S>]) -> Result<(), LabelError> {
        // Set must have at least 1 element
        if labels.len() == 0 {
            return Err(LabelError::EmptyLabelsSet);
        }

        // Set must not contain duplicate elements
        if labels.iter().contains_dups_by(|labels| labels.id()) {
            return Err(LabelError::DuplicateLabels);
        }

        // All labels must belong to the same circuit
        let circ = labels[0].circuit();
        if labels[1..]
            .iter()
            .any(|labels| labels.circuit().id() != circ.id())
        {
            return Err(LabelError::CircuitMismatch);
        }

        Ok(())
    }
}

impl<G> LabelsSet<G, Full>
where
    G: WireGroup + Clone,
{
    /// Returns delta for all labels in the set
    pub fn delta(&self) -> Delta {
        self.labels[0].delta()
    }

    fn generic_full_checks(labels: &[Labels<G, Full>]) -> Result<(), LabelError> {
        // All labels must have the same delta
        let delta = labels[0].delta();
        if labels[1..].iter().any(|labels| labels.delta() != delta) {
            return Err(LabelError::DeltaMismatch);
        }

        Ok(())
    }
}

impl<S> LabelsSet<Input, S>
where
    S: State,
{
    fn generic_input_checks(labels: &[Labels<Input, S>]) -> Result<(), LabelError> {
        // All inputs must be present
        let circ = labels[0].circuit();
        if labels.len() != circ.input_count() {
            return Err(LabelError::InvalidCount(
                circ.id().clone(),
                circ.input_count(),
                labels.len(),
            ));
        }

        Ok(())
    }
}

impl<S> LabelsSet<Output, S>
where
    S: State,
{
    fn generic_output_checks(labels: &[Labels<Output, S>]) -> Result<(), LabelError> {
        // All outputs must be present
        let circ = labels[0].circuit();
        if labels.len() != circ.output_count() {
            return Err(LabelError::InvalidCount(
                circ.id().clone(),
                circ.output_count(),
                labels.len(),
            ));
        }

        Ok(())
    }
}

impl LabelsSet<Input, Full> {
    /// Returns new label set after performing a series of validations
    pub fn new(mut labels: Vec<Labels<Input, Full>>) -> Result<Self, LabelError> {
        labels.sort_by_key(|labels| labels.index());

        Self::generic_checks(&labels)?;
        Self::generic_full_checks(&labels)?;
        Self::generic_input_checks(&labels)?;

        Ok(Self { labels })
    }

    /// Generates a full set of input wire labels for a circuit using the provided RNG.
    pub fn generate<R: Rng + CryptoRng>(rng: &mut R, circ: &Circuit, delta: Option<Delta>) -> Self {
        let delta = delta.unwrap_or_else(|| Delta::random(rng));

        Self {
            labels: circ
                .inputs()
                .iter()
                .map(|input| FullInputLabels::generate(rng, input.clone(), delta))
                .collect(),
        }
    }
}

impl LabelsSet<Input, Active> {
    /// Returns new label set after performing a series of validations
    pub fn new(mut labels: Vec<Labels<Input, Active>>) -> Result<Self, LabelError> {
        labels.sort_by_key(|labels| labels.index());

        Self::generic_checks(&labels)?;
        Self::generic_input_checks(&labels)?;

        Ok(Self { labels })
    }
}

impl LabelsSet<Output, Full> {
    /// Returns new label set after performing a series of validations
    pub fn new(mut labels: Vec<Labels<Output, Full>>) -> Result<Self, LabelError> {
        labels.sort_by_key(|labels| labels.index());

        Self::generic_checks(&labels)?;
        Self::generic_full_checks(&labels)?;
        Self::generic_output_checks(&labels)?;

        Ok(Self { labels })
    }
}

impl LabelsSet<Output, Active> {
    /// Returns new label set after performing a series of validations
    pub fn new(mut labels: Vec<Labels<Output, Active>>) -> Result<Self, LabelError> {
        labels.sort_by_key(|labels| labels.index());

        Self::generic_checks(&labels)?;
        Self::generic_output_checks(&labels)?;

        Ok(Self { labels })
    }
}

impl<G, S> Index<usize> for LabelsSet<G, S>
where
    G: WireGroup + Clone,
    S: State,
{
    type Output = Labels<G, S>;

    fn index(&self, index: usize) -> &Self::Output {
        &self.labels[index]
    }
}

#[cfg(test)]
mod tests {
    use std::{ops::IndexMut, sync::Arc};

    use super::*;
    use rstest::*;

    use mpc_circuits::{Circuit, CircuitId, Value, ADDER_64, AES_128_REVERSE};
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;

    #[fixture]
    pub fn circ() -> Arc<Circuit> {
        Circuit::load_bytes(ADDER_64).unwrap()
    }

    fn circ_id() -> CircuitId {
        Circuit::load_bytes(ADDER_64).unwrap().id().clone()
    }

    #[fixture]
    fn rng() -> ChaCha12Rng {
        ChaCha12Rng::seed_from_u64(0)
    }

    #[rstest]
    #[case(vec![], LabelError::EmptyLabelsSet)]
    #[case(vec![(0, Value::from(0u64))], LabelError::InvalidCount(circ_id(), 2, 1))]
    #[case(vec![(0, Value::from(0u64)), (1, Value::from(0u64)), (1, Value::from(0u64))], LabelError::DuplicateLabels)]
    fn test_labels_set_empty(
        circ: Arc<Circuit>,
        mut rng: ChaCha12Rng,
        #[case] values: Vec<(usize, Value)>,
        #[case] expected_err: LabelError,
    ) {
        let labels = LabelsSet::generate(&mut rng, &circ, None);
        let active_labels = values
            .into_iter()
            .map(|(id, value)| labels[id].select(&value).unwrap())
            .collect();

        let err = LabelsSet::<Input, Active>::new(active_labels).unwrap_err();

        assert_eq!(err, expected_err);
    }

    #[rstest]
    fn test_labels_set_delta_mismatch(circ: Arc<Circuit>, mut rng: ChaCha12Rng) {
        let labels = LabelsSet::generate(&mut rng, &circ, None);
        let labels_2 = LabelsSet::generate(&mut rng, &circ, None);

        let err = LabelsSet::<Input, Full>::new(vec![labels[0].clone(), labels_2[1].clone()])
            .unwrap_err();

        assert_eq!(err, LabelError::DeltaMismatch)
    }

    #[rstest]
    fn test_labels_set_circuit_mismatch(circ: Arc<Circuit>, mut rng: ChaCha12Rng) {
        let labels = LabelsSet::generate(&mut rng, &circ, None);

        let circ_2 = Circuit::load_bytes(AES_128_REVERSE).unwrap();
        let labels_2 = LabelsSet::generate(&mut rng, &circ_2, None);

        let err = LabelsSet::<Input, Active>::new(vec![
            labels[0].clone().select(&Value::from(0u64)).unwrap(),
            labels_2[1]
                .clone()
                .select(&Value::from(vec![0u8; 16]))
                .unwrap(),
        ])
        .unwrap_err();

        assert_eq!(err, LabelError::CircuitMismatch)
    }

    impl<G, S> IndexMut<usize> for LabelsSet<G, S>
    where
        G: WireGroup + Clone,
        S: State,
    {
        fn index_mut(&mut self, index: usize) -> &mut Self::Output {
            &mut self.labels[index]
        }
    }
}
