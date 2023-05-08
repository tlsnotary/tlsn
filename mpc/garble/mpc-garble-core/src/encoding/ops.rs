use std::ops::BitXor;

use mpc_circuits::types::TypeError;

use crate::{
    encoding_state::{Active, Full},
    EncodedValue, ValueError,
};

macro_rules! impl_encoded_xor {
    ($state:ty) => {
        impl BitXor for EncodedValue<$state> {
            type Output = Result<EncodedValue<$state>, ValueError>;

            fn bitxor(self, rhs: Self) -> Self::Output {
                match (&self, &rhs) {
                    (EncodedValue::Bit(a), EncodedValue::Bit(b)) => Ok(EncodedValue::Bit(a ^ b)),
                    (EncodedValue::U8(a), EncodedValue::U8(b)) => Ok(EncodedValue::U8(a ^ b)),
                    (EncodedValue::U16(a), EncodedValue::U16(b)) => Ok(EncodedValue::U16(a ^ b)),
                    (EncodedValue::U32(a), EncodedValue::U32(b)) => Ok(EncodedValue::U32(a ^ b)),
                    (EncodedValue::U64(a), EncodedValue::U64(b)) => Ok(EncodedValue::U64(a ^ b)),
                    (EncodedValue::U128(a), EncodedValue::U128(b)) => Ok(EncodedValue::U128(a ^ b)),
                    (EncodedValue::Array(a), EncodedValue::Array(b))
                        if self.value_type() == rhs.value_type() =>
                    {
                        Ok(EncodedValue::Array(
                            a.into_iter()
                                .zip(b.into_iter())
                                .map(|(a, b)| a ^ b)
                                .collect::<Result<Vec<_>, _>>()?,
                        ))
                    }
                    _ => Err(ValueError::TypeError(TypeError::UnexpectedType {
                        expected: self.value_type(),
                        actual: rhs.value_type(),
                    })),
                }
            }
        }

        impl BitXor for &EncodedValue<$state> {
            type Output = Result<EncodedValue<$state>, ValueError>;

            fn bitxor(self, rhs: Self) -> Self::Output {
                match (&self, &rhs) {
                    (EncodedValue::Bit(a), EncodedValue::Bit(b)) => Ok(EncodedValue::Bit(a ^ b)),
                    (EncodedValue::U8(a), EncodedValue::U8(b)) => Ok(EncodedValue::U8(a ^ b)),
                    (EncodedValue::U16(a), EncodedValue::U16(b)) => Ok(EncodedValue::U16(a ^ b)),
                    (EncodedValue::U32(a), EncodedValue::U32(b)) => Ok(EncodedValue::U32(a ^ b)),
                    (EncodedValue::U64(a), EncodedValue::U64(b)) => Ok(EncodedValue::U64(a ^ b)),
                    (EncodedValue::U128(a), EncodedValue::U128(b)) => Ok(EncodedValue::U128(a ^ b)),
                    (EncodedValue::Array(a), EncodedValue::Array(b))
                        if self.value_type() == rhs.value_type() =>
                    {
                        Ok(EncodedValue::Array(
                            a.into_iter()
                                .zip(b.into_iter())
                                .map(|(a, b)| a ^ b)
                                .collect::<Result<Vec<_>, _>>()?,
                        ))
                    }
                    _ => Err(ValueError::TypeError(TypeError::UnexpectedType {
                        expected: self.value_type(),
                        actual: rhs.value_type(),
                    })),
                }
            }
        }

        impl BitXor<EncodedValue<$state>> for &EncodedValue<$state> {
            type Output = Result<EncodedValue<$state>, ValueError>;

            fn bitxor(self, rhs: EncodedValue<$state>) -> Self::Output {
                match (&self, &rhs) {
                    (EncodedValue::Bit(a), EncodedValue::Bit(b)) => Ok(EncodedValue::Bit(a ^ b)),
                    (EncodedValue::U8(a), EncodedValue::U8(b)) => Ok(EncodedValue::U8(a ^ b)),
                    (EncodedValue::U16(a), EncodedValue::U16(b)) => Ok(EncodedValue::U16(a ^ b)),
                    (EncodedValue::U32(a), EncodedValue::U32(b)) => Ok(EncodedValue::U32(a ^ b)),
                    (EncodedValue::U64(a), EncodedValue::U64(b)) => Ok(EncodedValue::U64(a ^ b)),
                    (EncodedValue::U128(a), EncodedValue::U128(b)) => Ok(EncodedValue::U128(a ^ b)),
                    (EncodedValue::Array(a), EncodedValue::Array(b))
                        if self.value_type() == rhs.value_type() =>
                    {
                        Ok(EncodedValue::Array(
                            a.into_iter()
                                .zip(b.into_iter())
                                .map(|(a, b)| a ^ b)
                                .collect::<Result<Vec<_>, _>>()?,
                        ))
                    }
                    _ => Err(ValueError::TypeError(TypeError::UnexpectedType {
                        expected: self.value_type(),
                        actual: rhs.value_type(),
                    })),
                }
            }
        }

        impl BitXor<&EncodedValue<$state>> for EncodedValue<$state> {
            type Output = Result<EncodedValue<$state>, ValueError>;

            fn bitxor(self, rhs: &EncodedValue<$state>) -> Self::Output {
                match (&self, &rhs) {
                    (EncodedValue::Bit(a), EncodedValue::Bit(b)) => Ok(EncodedValue::Bit(a ^ b)),
                    (EncodedValue::U8(a), EncodedValue::U8(b)) => Ok(EncodedValue::U8(a ^ b)),
                    (EncodedValue::U16(a), EncodedValue::U16(b)) => Ok(EncodedValue::U16(a ^ b)),
                    (EncodedValue::U32(a), EncodedValue::U32(b)) => Ok(EncodedValue::U32(a ^ b)),
                    (EncodedValue::U64(a), EncodedValue::U64(b)) => Ok(EncodedValue::U64(a ^ b)),
                    (EncodedValue::U128(a), EncodedValue::U128(b)) => Ok(EncodedValue::U128(a ^ b)),
                    (EncodedValue::Array(a), EncodedValue::Array(b))
                        if self.value_type() == rhs.value_type() =>
                    {
                        Ok(EncodedValue::Array(
                            a.into_iter()
                                .zip(b.into_iter())
                                .map(|(a, b)| a ^ b)
                                .collect::<Result<Vec<_>, _>>()?,
                        ))
                    }
                    _ => Err(ValueError::TypeError(TypeError::UnexpectedType {
                        expected: self.value_type(),
                        actual: rhs.value_type(),
                    })),
                }
            }
        }
    };
}

impl_encoded_xor!(Active);
impl_encoded_xor!(Full);

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;

    use std::marker::PhantomData;

    use crate::{ChaChaEncoder, Encoder};
    use mpc_circuits::types::{StaticValueType, Value};
    use rand::{
        distributions::{Distribution, Standard},
        Rng, SeedableRng,
    };
    use rand_chacha::ChaCha12Rng;

    #[fixture]
    fn encoder() -> ChaChaEncoder {
        ChaChaEncoder::new([0u8; 32])
    }

    fn xor<const N: usize, T: BitXor<T, Output = T> + Copy>(a: [T; N], b: [T; N]) -> [T; N] {
        std::array::from_fn(|i| a[i] ^ b[i])
    }

    #[rstest]
    #[case::bit(PhantomData::<bool>)]
    #[case::u8(PhantomData::<u8>)]
    #[case::u16(PhantomData::<u16>)]
    #[case::u64(PhantomData::<u64>)]
    #[case::u64(PhantomData::<u64>)]
    #[case::u128(PhantomData::<u128>)]
    fn test_encoded_xor<T>(encoder: ChaChaEncoder, #[case] _pd: PhantomData<T>)
    where
        Standard: Distribution<T>,
        T: BitXor<T, Output = T> + StaticValueType + Default + Copy,
    {
        let mut rng = ChaCha12Rng::from_seed([0u8; 32]);

        let a: T = rng.gen();
        let b: T = rng.gen();

        let a_full: EncodedValue<_> = encoder.encode_by_type(0, &T::value_type()).into();
        let b_full: EncodedValue<_> = encoder.encode_by_type(1, &T::value_type()).into();
        let c_full = (&a_full ^ &b_full).unwrap();

        let a_active = a_full.select(a).unwrap();
        let b_active = b_full.select(b).unwrap();
        let c_active = (a_active ^ b_active).unwrap();

        let c = c_full.decode(&c_active).unwrap();
        let expected_c: Value = (a ^ b).into();

        assert_eq!(c, expected_c);
    }

    #[rstest]
    #[case::bit_array(PhantomData::<[bool; 16]>)]
    #[case::u8_array(PhantomData::<[u8; 16]>)]
    #[case::u16_array(PhantomData::<[u16; 16]>)]
    #[case::u32_array(PhantomData::<[u32; 16]>)]
    #[case::u64_array(PhantomData::<[u64; 16]>)]
    #[case::u128_array(PhantomData::<[u128; 16]>)]
    fn test_encoded_xor_array<T>(encoder: ChaChaEncoder, #[case] _pd: PhantomData<[T; 16]>)
    where
        Standard: Distribution<[T; 16]>,
        T: BitXor<T, Output = T> + StaticValueType + Default + Copy,
        [T; 16]: StaticValueType,
    {
        let mut rng = ChaCha12Rng::from_seed([0u8; 32]);

        let a: [T; 16] = rng.gen();
        let b: [T; 16] = rng.gen();

        let a_full: EncodedValue<_> = encoder.encode_by_type(0, &<[T; 16]>::value_type()).into();
        let b_full: EncodedValue<_> = encoder.encode_by_type(1, &<[T; 16]>::value_type()).into();
        let c_full = (&a_full ^ &b_full).unwrap();

        let a_active = a_full.select(a).unwrap();
        let b_active = b_full.select(b).unwrap();
        let c_active = (a_active ^ b_active).unwrap();

        let c = c_full.decode(&c_active).unwrap();
        let expected_c: Value = xor(a, b).into();

        assert_eq!(c, expected_c);
    }
}
