use crate::ShareConversionError;

/// The messages exchanged between sender and receiver
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Gf2ConversionMessage {
    seed: Vec<u8>,
    sender_tape: Vec<u128>,
}

impl From<([u8; 32], Vec<u128>)> for Gf2ConversionMessage {
    fn from(value: ([u8; 32], Vec<u128>)) -> Self {
        Self {
            seed: value.0.to_vec(),
            sender_tape: value.1.to_vec(),
        }
    }
}

impl TryInto<([u8; 32], Vec<u128>)> for Gf2ConversionMessage {
    type Error = ShareConversionError;

    fn try_into(self) -> Result<([u8; 32], Vec<u128>), Self::Error> {
        let seed: [u8; 32] = self
            .seed
            .try_into()
            .map_err(|_| ShareConversionError::SeedConversion)?;
        Ok((seed, self.sender_tape))
    }
}
