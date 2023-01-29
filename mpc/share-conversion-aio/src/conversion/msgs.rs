use crate::ShareConversionError;
use utils_aio::Channel;

/// A channel used for messaging of conversion protocols
pub type ShareConversionChannel = Box<dyn Channel<ShareConversionMessage, Error = std::io::Error>>;

/// The messages exchanged between sender and receiver
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ShareConversionMessage {
    seed: Vec<u8>,
    sender_tape: Vec<u128>,
}

impl From<([u8; 32], Vec<u128>)> for ShareConversionMessage {
    fn from(value: ([u8; 32], Vec<u128>)) -> Self {
        Self {
            seed: value.0.to_vec(),
            sender_tape: value.1.to_vec(),
        }
    }
}

impl TryFrom<ShareConversionMessage> for ([u8; 32], Vec<u128>) {
    type Error = ShareConversionError;

    fn try_from(value: ShareConversionMessage) -> Result<Self, Self::Error> {
        let seed: [u8; 32] = value
            .seed
            .try_into()
            .map_err(|_| ShareConversionError::SeedConversion)?;
        Ok((seed, value.sender_tape))
    }
}
