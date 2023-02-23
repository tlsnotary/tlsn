use crate::{fields::Field, ShareConversionCoreError};

/// The messages exchanged between sender and receiver
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ShareConversionMessage<T: Field> {
    Commitment(Commitment),
    Opening(Opening<T>),
}

/// Commitment to the rng seed
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Commitment(Vec<u8>);

impl From<[u8; 32]> for Commitment {
    fn from(value: [u8; 32]) -> Self {
        Self(value.to_vec())
    }
}

impl TryFrom<Commitment> for [u8; 32] {
    type Error = ShareConversionCoreError;

    fn try_from(value: Commitment) -> Result<Self, Self::Error> {
        let commitment: [u8; 32] = value
            .0
            .try_into()
            .map_err(|_| ShareConversionCoreError::MessageConversion)?;

        Ok(commitment)
    }
}

/// The opening, which is sent at the end of the protocol
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Opening<T: Field> {
    seed: Vec<u8>,
    salt: Vec<u8>,
    sender_tape: Vec<T>,
}

impl<T: Field> From<([u8; 32], [u8; 32], Vec<T>)> for Opening<T> {
    fn from(value: ([u8; 32], [u8; 32], Vec<T>)) -> Self {
        Self {
            seed: value.0.to_vec(),
            salt: value.1.to_vec(),
            sender_tape: value.2,
        }
    }
}

impl<T: Field> TryFrom<Opening<T>> for ([u8; 32], [u8; 32], Vec<T>) {
    type Error = ShareConversionCoreError;

    fn try_from(value: Opening<T>) -> Result<Self, Self::Error> {
        let seed: [u8; 32] = value
            .seed
            .try_into()
            .map_err(|_| ShareConversionCoreError::MessageConversion)?;
        let salt: [u8; 32] = value
            .salt
            .try_into()
            .map_err(|_| ShareConversionCoreError::MessageConversion)?;
        Ok((seed, salt, value.sender_tape))
    }
}
