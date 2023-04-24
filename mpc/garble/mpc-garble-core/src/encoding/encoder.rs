use mpc_circuits::types::{BinaryLength, ValueType};
use mpc_core::Block;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rand_core::OsRng;

use super::{state, value::Encode, Delta, EncodedValue, Label};

const DELTA_STREAM_ID: u64 = u64::MAX;

/// This trait is used to encode values using a global offset (delta).
///
/// Implementations of this trait should be _idempotent_, meaning that calling
/// `encode` multiple times with the same id should return the same result.
/// This way every value is assigned a unique encoding which can be regenerated
/// at any time, independent of the order in which values are encoded.
pub trait Encoder: Send + Sync {
    /// Returns encoder's rng seed
    fn seed(&self) -> Vec<u8>;

    /// Returns encoder's global offset
    fn delta(&self) -> Delta;

    /// Encodes a type using the provided stream id
    ///
    /// * `id` - Unique id of value
    fn encode<T: Encode + BinaryLength>(&self, id: u64) -> T::Encoded;

    /// Encodes a type using the provided stream id
    ///
    /// * `id` - Unique id of value
    /// * `ty` - Type of value
    fn encode_by_type(&self, id: u64, ty: &ValueType) -> EncodedValue<state::Full>;
}

/// Encodes values using the ChaCha algorithm.
#[derive(Debug)]
pub struct ChaChaEncoder {
    seed: [u8; 32],
    delta: Delta,
}

impl Default for ChaChaEncoder {
    fn default() -> Self {
        Self::new(OsRng.gen())
    }
}

impl ChaChaEncoder {
    /// Creates a new encoder with the provided seed
    ///
    /// * `seed` - 32-byte seed for ChaChaRng
    pub fn new(seed: [u8; 32]) -> Self {
        let mut rng = ChaCha20Rng::from_seed(seed);

        // Stream id u64::MAX is reserved to generate delta.
        // This way there is only ever 1 delta per seed
        rng.set_stream(DELTA_STREAM_ID);
        let delta = Delta::random(&mut rng);

        Self { seed, delta }
    }

    /// Returns the ChaChaRng for the provided stream id
    ///
    /// * `id` - Id of value
    fn get_rng(&self, id: u64) -> ChaCha20Rng {
        if id == DELTA_STREAM_ID {
            panic!("stream id {} is reserved", DELTA_STREAM_ID);
        }

        let mut rng = ChaCha20Rng::from_seed(self.seed);
        rng.set_stream(id);
        rng.set_word_pos(0);

        rng
    }
}

impl Encoder for ChaChaEncoder {
    fn seed(&self) -> Vec<u8> {
        self.seed.to_vec()
    }

    fn delta(&self) -> Delta {
        self.delta
    }

    fn encode<T: Encode + BinaryLength>(&self, id: u64) -> T::Encoded {
        let mut rng = self.get_rng(id);

        let labels = Block::random_vec(&mut rng, T::LEN)
            .into_iter()
            .map(Label::new)
            .collect::<Vec<_>>();

        T::encode(self.delta, &labels).expect("encoding should not fail")
    }

    fn encode_by_type(&self, id: u64, ty: &ValueType) -> EncodedValue<state::Full> {
        match ty {
            ValueType::Bit => self.encode::<bool>(id).into(),
            ValueType::U8 => self.encode::<u8>(id).into(),
            ValueType::U16 => self.encode::<u16>(id).into(),
            ValueType::U32 => self.encode::<u32>(id).into(),
            ValueType::U64 => self.encode::<u64>(id).into(),
            ValueType::U128 => self.encode::<u128>(id).into(),
            ValueType::Array(_, _) => {
                let mut rng = self.get_rng(id);

                let labels = Block::random_vec(&mut rng, ty.len())
                    .into_iter()
                    .map(Label::new)
                    .collect::<Vec<_>>();

                EncodedValue::<state::Full>::from_labels(ty.clone(), self.delta, &labels)
                    .expect("bit length should be correct")
            }
            _ => unimplemented!("encoding of type {:?} is not implemented", ty),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::encoding::{state, EncodedValue};
    use std::marker::PhantomData;

    use super::*;
    use rstest::*;

    #[fixture]
    fn encoder() -> ChaChaEncoder {
        ChaChaEncoder::new([0u8; 32])
    }

    #[rstest]
    #[case::bit(PhantomData::<bool>)]
    #[case::u8(PhantomData::<u8>)]
    #[case::u16(PhantomData::<u16>)]
    #[case::u64(PhantomData::<u64>)]
    #[case::u64(PhantomData::<u64>)]
    #[case::u128(PhantomData::<u128>)]
    fn test_encoder_idempotent<T: Encode + BinaryLength + Default>(
        encoder: ChaChaEncoder,
        #[case] _pd: PhantomData<T>,
    ) where
        T::Encoded: Into<EncodedValue<state::Full>>,
    {
        let encoded: EncodedValue<_> = encoder.encode::<T>(0).into();
        let encoded2: EncodedValue<_> = encoder.encode::<T>(0).into();

        assert_eq!(encoded, encoded2);
    }
}
