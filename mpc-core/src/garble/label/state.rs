use std::sync::Arc;

use mpc_circuits::Value;

use crate::garble::LabelError;

use super::{Delta, WireLabel, WireLabelPair};

mod sealed {
    pub trait Sealed {}

    impl Sealed for super::Full {}
    impl Sealed for super::Active {}
}

/// Marker trait for label state
pub trait State: sealed::Sealed {}

/// Full wire labels
#[derive(Debug, Clone, PartialEq)]
pub struct Full {
    /// Wire labels corresponding to logic low. The high labels are implicit because we can
    /// always derive a high label by doing: low XOR delta.
    pub(super) low: Arc<Vec<WireLabel>>,
    pub(super) delta: Delta,
}

impl State for Full {}

impl Full {
    pub(super) fn from_labels(low: Vec<WireLabel>, delta: Delta) -> Self {
        Self {
            low: Arc::new(low),
            delta,
        }
    }

    /// Returns active labels corresponding to the `value`
    pub(super) fn select(&self, value: &Value) -> Result<Active, LabelError> {
        if value.len() != self.low.len() {
            return Err(LabelError::InvalidValue(self.low.len(), value.len()));
        }
        Ok(Active {
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

    pub(super) fn iter(&self) -> impl Iterator<Item = WireLabelPair> + '_ {
        self.low
            .iter()
            .copied()
            .map(|low| low.to_pair(self.delta, false))
    }

    pub(super) fn to_labels(&self) -> Vec<WireLabelPair> {
        self.low
            .iter()
            .map(|low| low.to_pair(self.delta, false))
            .collect()
    }

    pub(super) fn from_decoding(
        active: Active,
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
    pub fn get(&self, idx: usize) -> WireLabelPair {
        self.low[idx].clone().to_pair(self.delta, false)
    }

    #[cfg(test)]
    pub fn set(&mut self, idx: usize, pair: WireLabelPair) {
        let mut low = (*self.low).clone();
        low[idx] = WireLabel::new(pair.id(), pair.low());
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
pub struct Active {
    pub(super) labels: Arc<Vec<WireLabel>>,
}

impl State for Active {}

impl Active {
    pub(super) fn from_labels(labels: Vec<WireLabel>) -> Self {
        Self {
            labels: Arc::new(labels),
        }
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = WireLabel> + '_ {
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
            .map(|label| label.value.to_be_bytes())
            .flatten()
            .collect()
    }

    #[cfg(test)]
    pub fn get(&self, idx: usize) -> WireLabel {
        self.labels[idx].clone()
    }

    #[cfg(test)]
    pub fn set(&mut self, idx: usize, label: WireLabel) {
        let mut labels = (*self.labels).clone();
        labels[idx] = label;
        self.labels = Arc::new(labels);
    }

    #[cfg(test)]
    pub fn push(&mut self, label: WireLabel) {
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
