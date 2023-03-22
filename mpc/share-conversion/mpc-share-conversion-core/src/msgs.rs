use super::Field;

/// The messages exchanged between sender and receiver
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ShareConversionMessage<T: Field> {
    SenderRecordings(SenderRecordings<T>),
}

/// A message containing the sender's seed and the conversion inputs
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SenderRecordings<T: Field> {
    pub seed: Vec<u8>,
    pub sender_inputs: Vec<T>,
}
