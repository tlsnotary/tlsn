use std::{ops::Index, sync::Arc};

use mpc_circuits::{Circuit, Input, Output, WireGroup};
use rand::{CryptoRng, Rng};
use utils::iter::DuplicateCheckBy;

use crate::garble::EncodingError;

use super::{state, Delta, Encoded, FullEncodedInput, GroupDecodingInfo};

/// A complete set of encoded wire groups. All labels are validated.
#[derive(Debug, Clone)]
pub struct EncodedSet<G, S>
where
    G: WireGroup + Clone,
    S: state::LabelState,
{
    groups: Vec<Encoded<G, S>>,
}

impl<G, S> EncodedSet<G, S>
where
    G: WireGroup + Clone,
    S: state::LabelState,
{
    /// Returns the circuit the set belongs to
    pub fn circuit(&self) -> Arc<Circuit> {
        self.groups[0].circuit()
    }

    /// Returns a reference to the labels in the set
    pub fn get_groups(&self) -> &[Encoded<G, S>] {
        &self.groups
    }

    /// Consumes set, returning all labels in the set
    pub fn to_inner(self) -> Vec<Encoded<G, S>> {
        self.groups
    }

    /// Returns a reference to the labels at that index or `None` if it is not part
    /// of the set.
    pub fn get(&self, index: usize) -> Option<&Encoded<G, S>> {
        self.groups.get(index)
    }

    /// Returns an iterator of the labels in the set
    pub fn iter(&self) -> impl Iterator<Item = &Encoded<G, S>> {
        self.groups.iter()
    }

    /// Returns the number of labels in the set
    pub fn len(&self) -> usize {
        self.groups.len()
    }

    fn generic_checks(groups: &[Encoded<G, S>]) -> Result<(), EncodingError> {
        // Set must have at least 1 element
        if groups.len() == 0 {
            return Err(EncodingError::EmptyEncodedSet);
        }

        // Set must not contain duplicate elements
        if groups.iter().contains_dups_by(|group| group.id()) {
            return Err(EncodingError::DuplicateGroups);
        }

        // All labels must belong to the same circuit
        let circ = groups[0].circuit();
        if groups[1..]
            .iter()
            .any(|group| group.circuit().id() != circ.id())
        {
            return Err(EncodingError::CircuitMismatch);
        }

        Ok(())
    }
}

impl<G> EncodedSet<G, state::Full>
where
    G: WireGroup + Clone,
{
    /// Returns delta for all labels in the set
    pub fn delta(&self) -> Delta {
        self.groups[0].delta()
    }

    /// Returns full set from active set and decoding information.
    pub fn from_decoding(
        active: EncodedSet<G, state::Active>,
        delta: Delta,
        decoding: Vec<GroupDecodingInfo<G>>,
    ) -> Result<EncodedSet<G, state::Full>, EncodingError> {
        if active.len() != decoding.len() {
            return Err(EncodingError::InvalidDecodingCount(
                active.len(),
                decoding.len(),
            ))?;
        }

        Ok(Self {
            groups: active
                .iter()
                .cloned()
                .zip(decoding)
                .map(|(active, decoding)| {
                    Encoded::<G, state::Full>::from_decoding(active, delta, decoding)
                })
                .collect::<Result<Vec<_>, _>>()?,
        })
    }

    fn generic_full_checks(groups: &[Encoded<G, state::Full>]) -> Result<(), EncodingError> {
        // All groups must have the same delta
        let delta = groups[0].delta();
        if groups[1..].iter().any(|group| group.delta() != delta) {
            return Err(EncodingError::DeltaMismatch);
        }

        Ok(())
    }
}

impl<S> EncodedSet<Input, S>
where
    S: state::LabelState,
{
    fn generic_input_checks(groups: &[Encoded<Input, S>]) -> Result<(), EncodingError> {
        // All inputs must be present
        let circ = groups[0].circuit();
        if groups.len() != circ.input_count() {
            return Err(EncodingError::InvalidCount(
                circ.id().clone(),
                circ.input_count(),
                groups.len(),
            ));
        }

        Ok(())
    }
}

impl<S> EncodedSet<Output, S>
where
    S: state::LabelState,
{
    fn generic_output_checks(groups: &[Encoded<Output, S>]) -> Result<(), EncodingError> {
        // All outputs must be present
        let circ = groups[0].circuit();
        if groups.len() != circ.output_count() {
            return Err(EncodingError::InvalidCount(
                circ.id().clone(),
                circ.output_count(),
                groups.len(),
            ));
        }

        Ok(())
    }
}

impl EncodedSet<Input, state::Full> {
    /// Returns new set after performing a series of validations
    pub fn new(mut groups: Vec<Encoded<Input, state::Full>>) -> Result<Self, EncodingError> {
        groups.sort_by_key(|group| group.index());

        Self::generic_checks(&groups)?;
        Self::generic_full_checks(&groups)?;
        Self::generic_input_checks(&groups)?;

        Ok(Self { groups })
    }

    /// Generates a full set of input wire labels for a circuit using the provided RNG.
    pub fn generate<R: Rng + CryptoRng>(rng: &mut R, circ: &Circuit, delta: Option<Delta>) -> Self {
        let delta = delta.unwrap_or_else(|| Delta::random(rng));

        Self {
            groups: circ
                .inputs()
                .iter()
                .map(|input| FullEncodedInput::generate(rng, input.clone(), delta))
                .collect(),
        }
    }
}

impl EncodedSet<Input, state::Active> {
    /// Returns new set after performing a series of validations
    pub fn new(mut groups: Vec<Encoded<Input, state::Active>>) -> Result<Self, EncodingError> {
        groups.sort_by_key(|group| group.index());

        Self::generic_checks(&groups)?;
        Self::generic_input_checks(&groups)?;

        Ok(Self { groups })
    }
}

impl EncodedSet<Output, state::Full> {
    /// Returns new set after performing a series of validations
    pub fn new(mut groups: Vec<Encoded<Output, state::Full>>) -> Result<Self, EncodingError> {
        groups.sort_by_key(|group| group.index());

        Self::generic_checks(&groups)?;
        Self::generic_full_checks(&groups)?;
        Self::generic_output_checks(&groups)?;

        Ok(Self { groups })
    }
}

impl EncodedSet<Output, state::Active> {
    /// Returns new set after performing a series of validations
    pub fn new(mut groups: Vec<Encoded<Output, state::Active>>) -> Result<Self, EncodingError> {
        groups.sort_by_key(|group| group.index());

        Self::generic_checks(&groups)?;
        Self::generic_output_checks(&groups)?;

        Ok(Self { groups })
    }
}

impl<G, S> Index<usize> for EncodedSet<G, S>
where
    G: WireGroup + Clone,
    S: state::LabelState,
{
    type Output = Encoded<G, S>;

    fn index(&self, index: usize) -> &Self::Output {
        &self.groups[index]
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
    #[case(vec![], EncodingError::EmptyEncodedSet)]
    #[case(vec![(0, Value::from(0u64))], EncodingError::InvalidCount(circ_id(), 2, 1))]
    #[case(vec![(0, Value::from(0u64)), (1, Value::from(0u64)), (1, Value::from(0u64))], EncodingError::DuplicateGroups)]
    fn test_set_empty(
        circ: Arc<Circuit>,
        mut rng: ChaCha12Rng,
        #[case] values: Vec<(usize, Value)>,
        #[case] expected_err: EncodingError,
    ) {
        let set = EncodedSet::generate(&mut rng, &circ, None);
        let active_groups = values
            .into_iter()
            .map(|(id, value)| set[id].select(&value).unwrap())
            .collect();

        let err = EncodedSet::<Input, state::Active>::new(active_groups).unwrap_err();

        assert_eq!(err, expected_err);
    }

    #[rstest]
    fn test_set_delta_mismatch(circ: Arc<Circuit>, mut rng: ChaCha12Rng) {
        let set = EncodedSet::generate(&mut rng, &circ, None);
        let set_2 = EncodedSet::generate(&mut rng, &circ, None);

        let err = EncodedSet::<Input, state::Full>::new(vec![set[0].clone(), set_2[1].clone()])
            .unwrap_err();

        assert_eq!(err, EncodingError::DeltaMismatch)
    }

    #[rstest]
    fn test_set_circuit_mismatch(circ: Arc<Circuit>, mut rng: ChaCha12Rng) {
        let set = EncodedSet::generate(&mut rng, &circ, None);

        let circ_2 = Circuit::load_bytes(AES_128_REVERSE).unwrap();
        let set_2 = EncodedSet::generate(&mut rng, &circ_2, None);

        let err = EncodedSet::<Input, state::Active>::new(vec![
            set[0].clone().select(&Value::from(0u64)).unwrap(),
            set_2[1]
                .clone()
                .select(&Value::from(vec![0u8; 16]))
                .unwrap(),
        ])
        .unwrap_err();

        assert_eq!(err, EncodingError::CircuitMismatch)
    }

    impl<G, S> IndexMut<usize> for EncodedSet<G, S>
    where
        G: WireGroup + Clone,
        S: state::LabelState,
    {
        fn index_mut(&mut self, index: usize) -> &mut Self::Output {
            &mut self.groups[index]
        }
    }
}
