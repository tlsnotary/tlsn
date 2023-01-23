use std::sync::Arc;

use mpc_circuits::Value;

use crate::garble::LabelError;

use super::{Delta, Label, LabelPair};

mod sealed {
    pub trait Sealed {}

    impl Sealed for super::FullLabels {}
    impl Sealed for super::ActiveLabels {}
}

/// Marker trait for label state
pub trait State: sealed::Sealed {}

/// Full wire labels
#[derive(Debug, Clone, PartialEq)]
pub struct FullLabels {
    /// Wire labels corresponding to logic low. The high labels are implicit because we can
    /// always derive a high label by doing: low XOR delta.
    pub(super) low: Arc<Vec<Label>>,
    pub(super) delta: Delta,
}

impl State for FullLabels {}

impl FullLabels {
    pub(super) fn from_labels(low: Vec<Label>, delta: Delta) -> Self {
        Self {
            low: Arc::new(low),
            delta,
        }
    }

    /// Returns number of labels
    pub fn len(&self) -> usize {
        self.low.len()
    }

    /// Returns active labels corresponding to the `value`
    pub fn select(&self, value: &Value) -> Result<ActiveLabels, LabelError> {
        if value.len() != self.low.len() {
            return Err(LabelError::InvalidValue(self.low.len(), value.len()));
        }
        Ok(ActiveLabels {
            labels: Arc::new(
                self.low
                    .iter()
                    .copied()
                    .zip(value.to_lsb0_bits().into_iter())
                    .map(|(low, level)| if level { low ^ self.delta } else { low })
                    .collect(),
            ),
        })
    }

    /// Returns iterator of label pairs
    pub fn iter(&self) -> impl Iterator<Item = LabelPair> + '_ {
        self.low
            .iter()
            .copied()
            .map(|low| low.to_pair(self.delta, false))
    }

    /// Returns vector of label pairs
    pub fn to_labels(&self) -> Vec<LabelPair> {
        self.low
            .iter()
            .map(|low| low.to_pair(self.delta, false))
            .collect()
    }

    pub(super) fn from_decoding(
        active: ActiveLabels,
        delta: Delta,
        decoding: Vec<bool>,
    ) -> Result<Self, LabelError> {
        if active.labels.len() != decoding.len() {
            return Err(LabelError::InvalidDecodingLength(
                active.labels.len(),
                decoding.len(),
            ));
        }
        Ok(Self {
            low: Arc::new(
                active
                    .iter()
                    .zip(decoding)
                    .map(|(label, decoding)| {
                        // If active label is logic high, flip it
                        if label.permute_bit() ^ decoding {
                            label ^ delta
                        } else {
                            label
                        }
                    })
                    .collect(),
            ),
            delta,
        })
    }

    #[cfg(test)]
    pub fn get(&self, idx: usize) -> LabelPair {
        self.low[idx].clone().to_pair(self.delta, false)
    }

    #[cfg(test)]
    pub fn set(&mut self, idx: usize, pair: LabelPair) {
        let mut low = (*self.low).clone();
        low[idx] = Label::new(pair.low());
        self.low = Arc::new(low);
    }

    #[cfg(test)]
    pub fn flip(&mut self, idx: usize) {
        let mut low = (*self.low).clone();
        low[idx] = low[idx] ^ self.delta;
        self.low = Arc::new(low);
    }
}

/// Active wire labels
#[derive(Debug, Clone, PartialEq)]
pub struct ActiveLabels {
    pub(super) labels: Arc<Vec<Label>>,
}

impl State for ActiveLabels {}

impl ActiveLabels {
    pub(super) fn from_labels(labels: Vec<Label>) -> Self {
        Self {
            labels: Arc::new(labels),
        }
    }

    /// Returns number of labels
    pub fn len(&self) -> usize {
        self.labels.len()
    }

    /// Returns iterator of labels
    pub fn iter(&self) -> impl Iterator<Item = Label> + '_ {
        self.labels.iter().copied()
    }

    pub(super) fn decode(&self, decoding: Vec<bool>) -> Result<Vec<bool>, LabelError> {
        if self.labels.len() != decoding.len() {
            return Err(LabelError::InvalidDecodingLength(
                self.labels.len(),
                decoding.len(),
            ));
        }

        Ok(decoding
            .into_iter()
            .zip(self.labels.iter())
            .map(|(decoding, label)| label.permute_bit() ^ decoding)
            .collect())
    }

    /// Serializes wire labels as bytes
    pub fn to_be_bytes(&self) -> Vec<u8> {
        self.labels
            .iter()
            .map(|label| label.value().to_be_bytes())
            .flatten()
            .collect()
    }

    #[cfg(test)]
    pub fn get(&self, idx: usize) -> Label {
        self.labels[idx].clone()
    }

    #[cfg(test)]
    pub fn set(&mut self, idx: usize, label: Label) {
        let mut labels = (*self.labels).clone();
        labels[idx] = label;
        self.labels = Arc::new(labels);
    }

    #[cfg(test)]
    pub fn push(&mut self, label: Label) {
        let mut labels = (*self.labels).clone();
        labels.push(label);
        self.labels = Arc::new(labels);
    }

    #[cfg(test)]
    pub fn pop(&mut self) {
        let mut labels = (*self.labels).clone();
        labels.pop();
        self.labels = Arc::new(labels);
    }
}
