use std::sync::Arc;

use mpc_circuits::{Circuit, GroupId, GroupValue, Value, WireGroup};

use super::{Active, Delta, Full, Label, LabelPair, LabelState, Labels};
use crate::{block::Block, garble::EncodingError};

/// Collection of validated labels corresponding to a wire group
#[derive(Debug, Clone, PartialEq)]
pub struct Encoded<G, S>
where
    G: WireGroup,
    S: LabelState,
{
    pub(crate) group: G,
    pub(crate) labels: Labels<S>,
}

impl<G, S> Encoded<G, S>
where
    G: WireGroup,
    S: LabelState,
{
    /// Returns encoded type, validating the provided labels using the associated group
    pub fn from_labels(group: G, labels: Labels<S>) -> Result<Self, EncodingError> {
        if group.len() != labels.len() {
            return Err(EncodingError::InvalidLabelCount(
                group.id().clone(),
                group.len(),
                labels.len(),
            ));
        }

        Ok(Self { group, labels })
    }

    /// Consumes `self` returning labels
    pub fn into_labels(self) -> Labels<S> {
        self.labels
    }
}

impl<G> Encoded<G, Full>
where
    G: WireGroup + Clone,
{
    /// Returns iterator to wire labels
    pub fn iter(&self) -> impl Iterator<Item = LabelPair> + '_ {
        self.labels.iter()
    }

    /// Returns iterator to wire labels as blocks
    pub fn iter_blocks(&self) -> impl Iterator<Item = [Block; 2]> + '_ {
        self.iter()
            .map(|label| [label.low().into_inner(), label.high().into_inner()])
    }

    /// Returns delta offset
    pub fn delta(&self) -> Delta {
        self.labels.get_delta()
    }

    /// Returns label decoding
    pub fn get_decoding(&self) -> GroupDecodingInfo<G> {
        GroupDecodingInfo {
            group: self.group.clone(),
            decoding: self.labels.get_decoding(),
        }
    }

    /// Returns full labels from decoding information
    pub fn from_decoding(
        active_labels: Encoded<G, Active>,
        delta: Delta,
        decoding: GroupDecodingInfo<G>,
    ) -> Result<Self, EncodingError> {
        Ok(Self {
            group: active_labels.group,
            labels: Labels::<Full>::from_decoding(active_labels.labels, delta, decoding.decoding)?,
        })
    }

    /// Returns active labels corresponding to a [`Value`]
    pub fn select(&self, value: &Value) -> Result<Encoded<G, Active>, EncodingError> {
        Ok(Encoded {
            group: self.group.clone(),
            labels: self.labels.select(value, self.group.bit_order())?,
        })
    }

    /// Validates whether the provided active labels are authentic
    pub fn validate(&self, labels: &Encoded<G, Active>) -> Result<(), EncodingError> {
        for (pair, label) in self.labels.iter().zip(labels.iter()) {
            if !(label == pair.low() || label == pair.high()) {
                return Err(EncodingError::InauthenticLabels(labels.group.id().clone()));
            }
        }
        Ok(())
    }

    #[cfg(test)]
    /// Returns labels at position idx
    ///
    /// Panics if idx is not in range
    pub fn get(&self, idx: usize) -> LabelPair {
        self.labels.get(idx)
    }

    #[cfg(test)]
    /// Set the value of labels at position idx
    ///
    /// Panics if idx is not in range
    pub fn set(&mut self, idx: usize, pair: LabelPair) {
        self.labels.set(idx, pair);
    }

    #[cfg(test)]
    /// Flip a label at position idx
    ///
    /// Panics if idx is not in range
    pub fn flip(&mut self, idx: usize) {
        self.labels.flip(idx);
    }
}

impl<G> Encoded<G, Active>
where
    G: WireGroup + Clone,
{
    /// Returns Encoded type, validating the provided labels using the associated group
    pub fn from_active_labels(group: G, labels: Labels<Active>) -> Result<Self, EncodingError> {
        if group.len() != labels.len() {
            return Err(EncodingError::InvalidLabelCount(
                group.id().clone(),
                group.len(),
                labels.len(),
            ));
        }

        Ok(Self { group, labels })
    }

    /// Returns iterator to wire labels
    pub fn iter(&self) -> impl Iterator<Item = Label> + '_ {
        self.labels.iter()
    }

    /// Returns iterator to wire labels as blocks
    pub fn iter_blocks(&self) -> impl Iterator<Item = Block> + '_ {
        self.iter().map(|label| label.into_inner())
    }

    /// Decode active labels to values using label decoding information.
    pub fn decode(&self, decoding: GroupDecodingInfo<G>) -> Result<GroupValue<G>, EncodingError> {
        if self.group.index() != decoding.group.index() {
            return Err(EncodingError::InvalidDecodingId(
                self.group.index(),
                decoding.group.index(),
            ));
        }

        // `bits` are guaranteed to have the correct number of bits for this group
        let bits = self.labels.decode(decoding.decoding)?;

        Ok(
            GroupValue::from_bits(self.group.clone(), bits, self.group.bit_order())
                .expect("Value should have correct bit count"),
        )
    }

    #[cfg(test)]
    /// Returns label at position idx
    ///
    /// Panics if idx is not in range
    pub fn get(&self, idx: usize) -> Label {
        self.labels.get(idx)
    }

    #[cfg(test)]
    /// Set the label at position idx
    ///
    /// Panics if idx is not in range
    pub fn set(&mut self, idx: usize, label: Label) {
        self.labels.set(idx, label);
    }
}

impl<G, S> WireGroup for Encoded<G, S>
where
    G: WireGroup,
    S: LabelState,
{
    fn circuit(&self) -> Arc<Circuit> {
        self.group.circuit()
    }

    fn index(&self) -> usize {
        self.group.index()
    }

    fn id(&self) -> &GroupId {
        self.group.id()
    }

    fn description(&self) -> &str {
        self.group.description()
    }

    fn value_type(&self) -> mpc_circuits::ValueType {
        self.group.value_type()
    }

    fn wires(&self) -> &[usize] {
        self.group.wires()
    }
}

/// Decoding info for garbled circuit wire labels.
/// (Not to be confused with wire ENcoding. A label is an ENcoding of a wire value (0 or 1). Thanks to
/// the Point-and-Permute technique, a label can be DEcoded back into a wire value just by comparing
/// its pointer bit (LSB) to the decoding info as explained below)
///
/// `w`   - circuit's wire
/// `W`   - active wire label
/// `W_0` - low wire label (it encodes the wire value 0)
/// `W_1` - high wire label (it encodes the wire value 1)
///
/// According to the Point-and-Permute technique:
///     
/// ---- W_1 = W_0 ^ Delta where LSB(Delta) = 1
///
/// ---- thus LSB(W_1) = LSB(W_0) ^ LSB(Delta) = LSB(W_0) ^ 1
///
/// We set DecodingInfo(w) to LSB(W_0).
///
/// The truth value of an active wire label W is computed:
///
/// `let truth_value = if LSB(W) == DecodingInfo(w) {0} else {1}`

#[derive(Debug, Clone, PartialEq)]
pub struct GroupDecodingInfo<G>
where
    G: WireGroup,
{
    group: G,
    pub(crate) decoding: Vec<bool>,
}

impl<G> GroupDecodingInfo<G>
where
    G: WireGroup,
{
    /// Returns label id
    pub fn id(&self) -> usize {
        self.group.index()
    }
}

/// Extracts active labels from a (sorted) slice containing all active labels
/// for a garbled circuit
///
/// Panics if provided an invalid group
pub(crate) fn extract_active_labels<G: WireGroup + Clone>(
    groups: &[G],
    labels: &[Label],
) -> Vec<Encoded<G, Active>> {
    groups
        .iter()
        .map(|group| {
            let labels = Labels::new_active(group.wires().iter().map(|id| labels[*id]).collect());
            Encoded::<G, Active>::from_active_labels(group.clone(), labels)
                .expect("Labels should be valid")
        })
        .collect()
}

/// Extracts full labels from a (sorted) slice containing all full labels
/// for a garbled circuit
///
/// Panics if provided an invalid group
pub(crate) fn extract_full_labels<G: WireGroup + Clone>(
    groups: &[G],
    delta: Delta,
    labels: &[LabelPair],
) -> Vec<Encoded<G, Full>> {
    groups
        .iter()
        .map(|group| {
            let labels = Labels::new_full(
                group.wires().iter().map(|id| labels[*id].low()).collect(),
                delta,
            );
            Encoded::<G, Full>::from_labels(group.clone(), labels).expect("Labels should be valid")
        })
        .collect()
}

/// Decodes set of active wire labels
pub(crate) fn decode_active_labels<G: WireGroup + Clone>(
    labels: &[Encoded<G, Active>],
    decoding: &[GroupDecodingInfo<G>],
) -> Result<Vec<GroupValue<G>>, EncodingError> {
    labels
        .iter()
        .zip(decoding.to_vec())
        .map(|(labels, decoding)| labels.decode(decoding))
        .collect::<Result<Vec<_>, EncodingError>>()
}

pub(crate) mod unchecked {
    use super::*;
    use mpc_circuits::WireGroup;

    #[derive(Debug, Clone)]
    pub struct UncheckedLabelsDecodingInfo {
        pub(crate) id: usize,
        pub(crate) decoding: Vec<bool>,
    }

    #[cfg(test)]
    impl<G> From<GroupDecodingInfo<G>> for UncheckedLabelsDecodingInfo
    where
        G: WireGroup,
    {
        fn from(decoding: GroupDecodingInfo<G>) -> Self {
            Self {
                id: decoding.group.index(),
                decoding: decoding.decoding,
            }
        }
    }

    impl<G> GroupDecodingInfo<G>
    where
        G: WireGroup,
    {
        /// Validates and converts to checked variant
        pub fn from_unchecked(
            group: G,
            unchecked: UncheckedLabelsDecodingInfo,
        ) -> Result<Self, EncodingError> {
            if group.index() != unchecked.id {
                return Err(EncodingError::InvalidDecodingId(
                    group.index(),
                    unchecked.id,
                ));
            } else if group.len() != unchecked.decoding.len() {
                return Err(EncodingError::InvalidDecodingCount(
                    group.len(),
                    unchecked.decoding.len(),
                ));
            }

            Ok(Self {
                group,
                decoding: unchecked.decoding,
            })
        }
    }

    #[cfg(test)]
    mod test {
        use super::*;
        use rstest::*;

        use mpc_circuits::{Circuit, Output, ADDER_64};

        #[fixture]
        fn circ() -> Arc<Circuit> {
            ADDER_64.clone()
        }

        #[fixture]
        fn output(circ: Arc<Circuit>) -> Output {
            circ.output(0).unwrap()
        }

        #[fixture]
        fn unchecked_labels_decoding_info(output: Output) -> UncheckedLabelsDecodingInfo {
            UncheckedLabelsDecodingInfo {
                id: output.index(),
                decoding: vec![false; output.len()],
            }
        }

        #[rstest]
        fn test_labels_decoding_info(
            output: Output,
            unchecked_labels_decoding_info: UncheckedLabelsDecodingInfo,
        ) {
            GroupDecodingInfo::from_unchecked(output, unchecked_labels_decoding_info).unwrap();
        }

        #[rstest]
        fn test_output_labels_decoding_info_wrong_id(
            output: Output,
            mut unchecked_labels_decoding_info: UncheckedLabelsDecodingInfo,
        ) {
            unchecked_labels_decoding_info.id += 1;
            let err = GroupDecodingInfo::from_unchecked(output, unchecked_labels_decoding_info)
                .unwrap_err();
            assert!(matches!(err, EncodingError::InvalidDecodingId(_, _)))
        }

        #[rstest]
        fn test_output_labels_decoding_info_wrong_count(
            output: Output,
            mut unchecked_labels_decoding_info: UncheckedLabelsDecodingInfo,
        ) {
            unchecked_labels_decoding_info.decoding.pop();
            let err = GroupDecodingInfo::from_unchecked(output, unchecked_labels_decoding_info)
                .unwrap_err();
            assert!(matches!(err, EncodingError::InvalidDecodingCount(_, _)))
        }
    }
}
