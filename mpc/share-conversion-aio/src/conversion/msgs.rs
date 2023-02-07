use crate::ShareConversionError;
use share_conversion_core::fields::Field;
use utils_aio::Channel;

/// A channel used by conversion protocols for messaging
pub type ShareConversionChannel<T> =
    Box<dyn Channel<ShareConversionMessage<T>, Error = std::io::Error>>;

/// The messages exchanged between sender and receiver
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ShareConversionMessage<T: Field> {
    pub seed: Vec<u8>,
    pub sender_tape: Vec<T>,
}

impl<T: Field> From<([u8; 32], Vec<T>)> for ShareConversionMessage<T> {
    fn from(value: ([u8; 32], Vec<T>)) -> Self {
        Self {
            seed: value.0.to_vec(),
            sender_tape: value.1.to_vec(),
        }
    }
}

impl<T: Field> TryFrom<ShareConversionMessage<T>> for ([u8; 32], Vec<T>) {
    type Error = ShareConversionError;

    fn try_from(value: ShareConversionMessage<T>) -> Result<Self, Self::Error> {
        let seed: [u8; 32] = value
            .seed
            .try_into()
            .map_err(|_| ShareConversionError::SeedConversion)?;
        Ok((seed, value.sender_tape))
    }
}
