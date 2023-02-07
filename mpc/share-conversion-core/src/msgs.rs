use super::Field;

/// The messages exchanged between sender and receiver
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ShareConversionMessage<T: Field> {
    pub sender_recordings: SenderRecordings<T>,
}

/// A message containing the sender's seed and the conversion inputs
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SenderRecordings<T: Field> {
    pub seed: Vec<u8>,
    pub sender_inputs: Vec<T>,
}

impl<T: Field> From<SenderRecordings<T>> for ShareConversionMessage<T> {
    fn from(value: SenderRecordings<T>) -> Self {
        Self {
            sender_recordings: value,
        }
    }
}

impl<T: Field> From<ShareConversionMessage<T>> for SenderRecordings<T> {
    fn from(value: ShareConversionMessage<T>) -> Self {
        value.sender_recordings
    }
}
