use std::{iter::Peekable, marker::PhantomData};

/// Zero-sized type used to represent LSB0 bit order.
pub struct Lsb0;
/// Zero-sized type used to represent MSB0 bit order.
pub struct Msb0;

pub struct BitStringIterator<'a> {
    string: &'a str,
    pos: usize,
}

impl<'a> Iterator for BitStringIterator<'a> {
    type Item = bool;

    fn next(&mut self) -> Option<Self::Item> {
        let Some(bit) = self.string.chars().nth(self.pos) else {
            return None;
        };

        self.pos += 1;

        let bit = match bit {
            '1' => true,
            '0' => false,
            _ => {
                panic!("string contains a character other than '0' or '1'")
            }
        };

        Some(bit)
    }
}

/// Trait for converting from bit strings to bit iterators.
pub trait StrToBits<'a> {
    /// Converts a bit string to an iterator of bits.
    ///
    /// Panics if the string contains characters other than '0' or '1'.
    fn to_bit_iter(&'a self) -> BitStringIterator<'a>;

    /// Converts a bit string to a bit vec.
    ///
    /// Panics if the string contains characters other than '0' or '1'.
    fn to_bit_vec(&'a self) -> Vec<bool> {
        self.to_bit_iter().collect()
    }
}

impl<'a, T> StrToBits<'a> for T
where
    T: AsRef<str>,
{
    fn to_bit_iter(&'a self) -> BitStringIterator<'a> {
        BitStringIterator {
            string: self.as_ref(),
            pos: 0,
        }
    }
}

/// Trait used for parsing a value from an iterator of bits.
pub trait FromBits {
    /// Parses a value from an iterator of bits in LSB0 order.
    ///
    /// Panics if the iterator yields fewer than `Self::BITS` bits.
    fn from_lsb0(iter: impl IntoIterator<Item = bool>) -> Self;

    /// Parses a value from an iterator of bits in MSB0 order.
    ///
    /// Panics if the iterator yields fewer than `Self::BITS` bits.
    fn from_msb0(iter: impl IntoIterator<Item = bool>) -> Self;
}

macro_rules! impl_from_bits {
    ($typ:ty) => {
        impl FromBits for $typ {
            fn from_lsb0(iter: impl IntoIterator<Item = bool>) -> Self {
                let mut iter = iter.into_iter();

                let mut value = <$typ>::default();

                for i in 0..<$typ>::BITS {
                    let Some(bit) = iter.next() else {
                        panic!("Bit iterator yielded fewer bits than expected, got {}, expected {}", i, <$typ>::BITS);
                    };

                    value |= (bit as $typ) << i;
                }

                value
            }

            fn from_msb0(iter: impl IntoIterator<Item = bool>) -> Self {
                let mut iter = iter.into_iter();

                let mut value = <$typ>::default();

                for i in 0..<$typ>::BITS {
                    let Some(bit) = iter.next() else {
                        panic!("Bit iterator yielded fewer bits than expected, got {}, expected {}", i, <$typ>::BITS);
                    };

                    value |= (bit as $typ) << ((<$typ>::BITS - 1) - i);
                }

                value
            }
        }
    };
}

impl_from_bits!(u8);
impl_from_bits!(u16);
impl_from_bits!(u32);
impl_from_bits!(u64);
impl_from_bits!(u128);

pub struct UintIterator<T, Ord> {
    bit_order: PhantomData<Ord>,
    value: T,
    pos: usize,
}

macro_rules! impl_uint_iter {
    ($typ:ty) => {
        impl Iterator for UintIterator<$typ, Lsb0> {
            type Item = bool;

            fn next(&mut self) -> Option<bool> {
                if self.pos == <$typ>::BITS as usize {
                    return None;
                }

                let bit = (self.value & (1 << self.pos)) != 0;

                self.pos += 1;

                Some(bit)
            }
        }

        impl Iterator for UintIterator<$typ, Msb0> {
            type Item = bool;

            fn next(&mut self) -> Option<bool> {
                if self.pos == <$typ>::BITS as usize {
                    return None;
                }

                let bit = (self.value & (1 << (<$typ>::BITS as usize - self.pos - 1))) != 0;

                self.pos += 1;

                Some(bit)
            }
        }
    };
}

impl_uint_iter!(u8);
impl_uint_iter!(u16);
impl_uint_iter!(u32);
impl_uint_iter!(u64);
impl_uint_iter!(u128);

pub struct BitParser<I, V, Ord>
where
    I: Iterator<Item = bool>,
    V: FromBits,
{
    bit_order: PhantomData<Ord>,
    value: PhantomData<V>,
    iter: Peekable<I>,
}

impl<I, V> Iterator for BitParser<I, V, Lsb0>
where
    I: Iterator<Item = bool>,
    V: FromBits,
{
    type Item = V;

    fn next(&mut self) -> Option<V> {
        // Check if there are any bits left in the iterator,
        // otherwise return None.
        if let Some(_) = self.iter.peek() {
            Some(V::from_lsb0(&mut self.iter))
        } else {
            None
        }
    }
}

impl<I, V> Iterator for BitParser<I, V, Msb0>
where
    I: Iterator<Item = bool>,
    V: FromBits,
{
    type Item = V;

    fn next(&mut self) -> Option<V> {
        // Check if there are any bits left in the iterator,
        // otherwise return None.
        if let Some(_) = self.iter.peek() {
            Some(V::from_msb0(&mut self.iter))
        } else {
            None
        }
    }
}

/// Trait used for parsing an iterator of values from an iterator of bits.
pub trait IterFromBits<V>
where
    Self: IntoIterator<Item = bool>,
    V: FromBits,
{
    /// Parses an iterator of values from an iterator of bits in LSB0 order.
    ///
    /// Panics if the iterator does not yield a multiple of `V::BITS` bits.
    fn iter_from_lsb0(self) -> BitParser<<Self as IntoIterator>::IntoIter, V, Lsb0>;

    /// Parses an iterator of values from an iterator of bits in MSB0 order.
    ///
    /// Panics if the iterator does not yield a multiple of `V::BITS` bits.
    fn iter_from_msb0(self) -> BitParser<<Self as IntoIterator>::IntoIter, V, Msb0>;
}

impl<I, V> IterFromBits<V> for I
where
    I: IntoIterator<Item = bool>,
    V: FromBits,
{
    fn iter_from_lsb0(self) -> BitParser<<Self as IntoIterator>::IntoIter, V, Lsb0> {
        BitParser {
            bit_order: PhantomData::<Lsb0>,
            value: PhantomData::<V>,
            iter: self.into_iter().peekable(),
        }
    }

    fn iter_from_msb0(self) -> BitParser<<Self as IntoIterator>::IntoIter, V, Msb0> {
        BitParser {
            bit_order: PhantomData::<Msb0>,
            value: PhantomData::<V>,
            iter: self.into_iter().peekable(),
        }
    }
}

impl<V> FromBits for Vec<V>
where
    V: FromBits,
{
    fn from_lsb0(iter: impl IntoIterator<Item = bool>) -> Self {
        iter.into_iter().iter_from_lsb0().collect()
    }

    fn from_msb0(iter: impl IntoIterator<Item = bool>) -> Self {
        iter.into_iter().iter_from_msb0().collect()
    }
}

/// Trait for converting types to bit iterators.
pub trait ToBitsIter {
    type Lsb0Iter: Iterator<Item = bool>;
    type Msb0Iter: Iterator<Item = bool>;

    /// Converts into an iterator of LSB0 bits.
    fn into_lsb0_iter(self) -> Self::Lsb0Iter;

    /// Converts into an iterator of MSB0 bits.
    fn into_msb0_iter(self) -> Self::Msb0Iter;
}

pub trait ToBits {
    /// Converts into an LSB0 bit vector.
    fn into_lsb0(self) -> Vec<bool>;

    /// Converts into an LSB0 bit vector.
    fn into_lsb0_boxed(self: Box<Self>) -> Vec<bool>;

    /// Converts into an MSB0 bit vector.
    fn into_msb0(self) -> Vec<bool>;

    /// Converts into an MSB0 bit vector.
    fn into_msb0_boxed(self: Box<Self>) -> Vec<bool>;
}

impl ToBitsIter for bool {
    type Lsb0Iter = std::iter::Once<bool>;
    type Msb0Iter = std::iter::Once<bool>;

    fn into_lsb0_iter(self) -> Self::Lsb0Iter {
        std::iter::once(self)
    }

    fn into_msb0_iter(self) -> Self::Msb0Iter {
        std::iter::once(self)
    }
}

impl<const N: usize> ToBitsIter for [bool; N] {
    type Lsb0Iter = std::array::IntoIter<bool, N>;
    type Msb0Iter = std::array::IntoIter<bool, N>;

    fn into_lsb0_iter(self) -> Self::Lsb0Iter {
        self.into_iter()
    }

    fn into_msb0_iter(self) -> Self::Msb0Iter {
        self.into_iter()
    }
}

impl ToBitsIter for Vec<bool> {
    type Lsb0Iter = std::vec::IntoIter<bool>;
    type Msb0Iter = std::vec::IntoIter<bool>;

    fn into_lsb0_iter(self) -> Self::Lsb0Iter {
        self.into_iter()
    }

    fn into_msb0_iter(self) -> Self::Msb0Iter {
        self.into_iter()
    }
}

macro_rules! impl_uint_to_bits {
    ($typ:ty) => {
        impl ToBitsIter for $typ {
            type Lsb0Iter = UintIterator<$typ, Lsb0>;
            type Msb0Iter = UintIterator<$typ, Msb0>;

            fn into_lsb0_iter(self) -> UintIterator<$typ, Lsb0> {
                UintIterator {
                    bit_order: PhantomData::<Lsb0>,
                    value: self,
                    pos: 0,
                }
            }

            fn into_msb0_iter(self) -> UintIterator<$typ, Msb0> {
                UintIterator {
                    bit_order: PhantomData::<Msb0>,
                    value: self,
                    pos: 0,
                }
            }
        }

        impl<const N: usize> ToBitsIter for [$typ; N] {
            type Lsb0Iter = std::iter::FlatMap<
                std::array::IntoIter<$typ, N>,
                UintIterator<$typ, Lsb0>,
                fn($typ) -> <$typ as ToBitsIter>::Lsb0Iter,
            >;
            type Msb0Iter = std::iter::FlatMap<
                std::array::IntoIter<$typ, N>,
                UintIterator<$typ, Msb0>,
                fn($typ) -> <$typ as ToBitsIter>::Msb0Iter,
            >;

            fn into_lsb0_iter(self) -> Self::Lsb0Iter {
                self.into_iter().flat_map(|v| v.into_lsb0_iter())
            }

            fn into_msb0_iter(self) -> Self::Msb0Iter {
                self.into_iter().flat_map(|v| v.into_msb0_iter())
            }
        }

        impl ToBitsIter for Vec<$typ> {
            type Lsb0Iter = std::iter::FlatMap<
                std::vec::IntoIter<$typ>,
                UintIterator<$typ, Lsb0>,
                fn($typ) -> <$typ as ToBitsIter>::Lsb0Iter,
            >;
            type Msb0Iter = std::iter::FlatMap<
                std::vec::IntoIter<$typ>,
                UintIterator<$typ, Msb0>,
                fn($typ) -> <$typ as ToBitsIter>::Msb0Iter,
            >;

            fn into_lsb0_iter(self) -> Self::Lsb0Iter {
                self.into_iter().flat_map(|v| v.into_lsb0_iter())
            }

            fn into_msb0_iter(self) -> Self::Msb0Iter {
                self.into_iter().flat_map(|v| v.into_msb0_iter())
            }
        }

        impl ToBits for $typ {
            fn into_lsb0(self) -> Vec<bool> {
                self.into_lsb0_iter().collect()
            }

            fn into_lsb0_boxed(self: Box<Self>) -> Vec<bool> {
                self.into_lsb0_iter().collect()
            }

            fn into_msb0(self) -> Vec<bool> {
                self.into_msb0_iter().collect()
            }

            fn into_msb0_boxed(self: Box<Self>) -> Vec<bool> {
                self.into_msb0_iter().collect()
            }
        }
    };
}

impl_uint_to_bits!(u8);
impl_uint_to_bits!(u16);
impl_uint_to_bits!(u32);
impl_uint_to_bits!(u64);
impl_uint_to_bits!(u128);

pub struct BitIterator<I, V, Ord> {
    bit_order: PhantomData<Ord>,
    inner_iter: Option<V>,
    outer_iter: I,
}

impl<I, V> Iterator for BitIterator<I, <V as ToBitsIter>::Lsb0Iter, Lsb0>
where
    I: Iterator<Item = V>,
    V: ToBitsIter,
{
    type Item = bool;

    fn next(&mut self) -> Option<bool> {
        // If inner_iter is set, pull from it.
        let Some(inner_iter) = self.inner_iter.as_mut() else {
            // If inner_iter is not set, pull from outer_iter.
            // If outer_iter is empty, return None.
            let Some(value) = self.outer_iter.next() else {
                return None;
            };

            // Set inner_iter to the next value.
            self.inner_iter = Some(value.into_lsb0_iter());

            return self.next();
        };

        let Some(bit) = inner_iter.next() else {
            // If inner_iter is empty, set it to None.
            self.inner_iter = None;

            return self.next();
        };

        Some(bit)
    }
}

impl<I, V> Iterator for BitIterator<I, <V as ToBitsIter>::Msb0Iter, Msb0>
where
    I: Iterator<Item = V>,
    V: ToBitsIter,
{
    type Item = bool;

    fn next(&mut self) -> Option<bool> {
        // If inner_iter is set, pull from it.
        let Some(inner_iter) = self.inner_iter.as_mut() else {
            // If inner_iter is not set, pull from outer_iter.
            // If outer_iter is empty, return None.
            let Some(value) = self.outer_iter.next() else {
                return None;
            };

            // Set inner_iter to the next value.
            self.inner_iter = Some(value.into_msb0_iter());

            return self.next();
        };

        let Some(bit) = inner_iter.next() else {
            // If inner_iter is empty, set it to None.
            self.inner_iter = None;

            return self.next();
        };

        Some(bit)
    }
}

/// Trait for converting an iterator of values to an iterator of bits.
pub trait IterToBits
where
    Self: IntoIterator,
{
    type Item: ToBitsIter;
    type Lsb0Iter: Iterator<Item = bool>;
    type Msb0Iter: Iterator<Item = bool>;

    fn into_lsb0_iter(self) -> Self::Lsb0Iter;

    fn into_lsb0(self) -> Vec<bool>;

    fn into_msb0_iter(self) -> Self::Msb0Iter;

    fn into_msb0(self) -> Vec<bool>;
}

impl<I, V> IterToBits for I
where
    I: IntoIterator<Item = V>,
    V: ToBitsIter,
{
    type Item = V;
    type Lsb0Iter = BitIterator<<I as IntoIterator>::IntoIter, <V as ToBitsIter>::Lsb0Iter, Lsb0>;
    type Msb0Iter = BitIterator<<I as IntoIterator>::IntoIter, <V as ToBitsIter>::Msb0Iter, Msb0>;

    fn into_lsb0_iter(self) -> Self::Lsb0Iter {
        BitIterator {
            bit_order: PhantomData::<Lsb0>,
            inner_iter: None,
            outer_iter: self.into_iter(),
        }
    }

    fn into_lsb0(self) -> Vec<bool> {
        self.into_lsb0_iter().collect()
    }

    fn into_msb0_iter(self) -> Self::Msb0Iter {
        BitIterator {
            bit_order: PhantomData::<Msb0>,
            inner_iter: None,
            outer_iter: self.into_iter(),
        }
    }

    fn into_msb0(self) -> Vec<bool> {
        self.into_msb0_iter().collect()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rstest::*;

    #[rstest]
    #[case::empty_string("", vec![])]
    #[case::one_bit_1("1", vec![true])]
    #[case::one_bit_0("0", vec![false])]
    #[case("0101", vec![false, true, false, true])]
    #[should_panic]
    #[case::non_binary_char("a", vec![])]
    fn test_string_to_boolvec(#[case] bits: &str, #[case] expected: Vec<bool>) {
        let bits: Vec<bool> = bits.to_bit_vec();

        assert_eq!(bits, expected);
    }

    #[rstest]
    #[case::single_byte_1("10000000", vec![1u8])]
    #[case::single_byte_0("00000000", vec![0u8])]
    #[case::single_byte_255("11111111", vec![255u8])]
    #[case::multi_byte("0000000010000000", vec![0u8, 1u8])]
    #[should_panic]
    #[case::missing_bit("0000000", vec![])]
    #[should_panic]
    #[case::extra_bit("000000000", vec![0u8])]
    fn test_lsb0_to_bytes(#[case] bits: &str, #[case] expected: Vec<u8>) {
        let bytes: Vec<u8> = Vec::from_lsb0(bits.to_bit_iter());

        assert_eq!(bytes, expected);
    }

    #[rstest]
    #[case::single_byte_1("00000001", vec![1u8])]
    #[case::single_byte_0("00000000", vec![0u8])]
    #[case::single_byte_255("11111111", vec![255u8])]
    #[case::multi_byte("0000000000000001", vec![0u8, 1u8])]
    #[should_panic]
    #[case::missing_bit("0000000", vec![])]
    #[should_panic]
    #[case::extra_bit("000000000", vec![0u8])]
    fn test_msb0_to_bytes(#[case] bits: &str, #[case] expected: Vec<u8>) {
        let bytes: Vec<u8> = Vec::from_msb0(bits.to_bit_iter());

        assert_eq!(bytes, expected);
    }

    #[rstest]
    #[case::single_byte_1(vec![1u8], "10000000")]
    #[case::single_byte_0(vec![0u8], "00000000")]
    #[case::single_byte_255(vec![255u8], "11111111")]
    #[case::multi_byte(vec![0u8, 1u8], "0000000010000000")]
    #[case::empty(vec![], "")]
    fn test_bytes_to_lsb0(#[case] bytes: Vec<u8>, #[case] expected: &str) {
        let expected = expected.to_bit_vec();

        let bits: Vec<bool> = bytes.into_lsb0();

        assert_eq!(bits, expected);
    }

    #[rstest]
    #[case::single_byte_1(vec![1u8], "00000001")]
    #[case::single_byte_0(vec![0u8], "00000000")]
    #[case::single_byte_255(vec![255u8], "11111111")]
    #[case::multi_byte(vec![0u8, 1u8], "0000000000000001")]
    #[case::empty(vec![], "")]
    fn test_bytes_to_msb0(#[case] bytes: Vec<u8>, #[case] expected: &str) {
        let expected = expected.to_bit_vec();

        let bits: Vec<bool> = bytes.into_msb0();

        assert_eq!(bits, expected);
    }

    #[rstest]
    #[case(format!("{:08b}", 0u8), 0u8)]
    #[case(format!("{:08b}", 1u8), 1u8)]
    #[case(format!("{:08b}", u8::MAX), u8::MAX)]
    #[case(format!("{:016b}", 0u16), 0u16)]
    #[case(format!("{:016b}", 1u16), 1u16)]
    #[case(format!("{:016b}", u16::MAX), u16::MAX)]
    #[case(format!("{:032b}", 0u32), 0u32)]
    #[case(format!("{:032b}", 1u32), 1u32)]
    #[case(format!("{:032b}", u32::MAX), u32::MAX)]
    #[case(format!("{:064b}", 0u64), 0u64)]
    #[case(format!("{:064b}", 1u64), 1u64)]
    #[case(format!("{:064b}", u64::MAX), u64::MAX)]
    #[case(format!("{:0128b}", 0u128), 0u128)]
    #[case(format!("{:0128b}", 1u128), 1u128)]
    #[case(format!("{:0128b}", u128::MAX), u128::MAX)]
    fn test_from_bits<T: FromBits + PartialEq + std::fmt::Debug>(
        #[case] bits: impl AsRef<str>,
        #[case] expected: T,
    ) {
        let msb_value = T::from_msb0(bits.to_bit_iter());

        let lsb_bits = bits.as_ref().chars().rev().collect::<String>();
        let lsb_value = T::from_lsb0(lsb_bits.to_bit_iter());

        assert_eq!(msb_value, expected);
        assert_eq!(lsb_value, expected);
    }

    #[rstest]
    #[case::u8(format!("{:08b}{:08b}", 1u8, 2u8), vec![1u8, 2u8])]
    #[case::u16(format!("{:016b}{:016b}", 1u16, 2u16), vec![1u16, 2u16])]
    #[case::u32(format!("{:032b}{:032b}", 1u32, 2u32), vec![1u32, 2u32])]
    #[case::u64(format!("{:064b}{:064b}", 1u64, 2u64), vec![1u64, 2u64])]
    #[case::u128(format!("{:0128b}{:0128b}", 1u128, 2u128), vec![1u128, 2u128])]
    #[should_panic]
    #[case::missing_bit(format!("{:08b}{:07b}", 1u8, 2u8), vec![1u8, 2u8])]
    fn test_iter_from_bits<T: FromBits + PartialEq + std::fmt::Debug>(
        #[case] bits: impl AsRef<str>,
        #[case] mut expected: Vec<T>,
    ) {
        let msb_value = Vec::<T>::from_msb0(bits.to_bit_iter());

        assert_eq!(msb_value, expected);

        let lsb_bits = bits.as_ref().chars().rev().collect::<String>();
        let lsb_value = Vec::<T>::from_lsb0(lsb_bits.to_bit_iter());

        expected.reverse();

        assert_eq!(lsb_value, expected);
    }

    #[rstest]
    #[case(0u8, format!("{:08b}", 0u8))]
    #[case(1u8, format!("{:08b}", 1u8))]
    #[case(u8::MAX, format!("{:08b}", u8::MAX))]
    #[case(0u16, format!("{:016b}", 0u16))]
    #[case(1u16, format!("{:016b}", 1u16))]
    #[case(u16::MAX, format!("{:016b}", u16::MAX))]
    #[case(0u32, format!("{:032b}", 0u32))]
    #[case(1u32, format!("{:032b}", 1u32))]
    #[case(u32::MAX, format!("{:032b}", u32::MAX))]
    #[case(0u64, format!("{:064b}", 0u64))]
    #[case(1u64, format!("{:064b}", 1u64))]
    #[case(u64::MAX, format!("{:064b}", u64::MAX))]
    #[case(0u128, format!("{:0128b}", 0u128))]
    #[case(1u128, format!("{:0128b}", 1u128))]
    #[case(u128::MAX, format!("{:0128b}", u128::MAX))]
    fn test_to_bits(#[case] value: impl ToBits + Copy, #[case] expected: impl AsRef<str>) {
        let lsb0_bits = value.into_lsb0();
        let msb0_bits = value.into_msb0();

        let mut expected = expected.as_ref().to_bit_vec();

        assert_eq!(msb0_bits, expected);

        expected.reverse();

        assert_eq!(lsb0_bits, expected);
    }

    #[rstest]
    #[case(vec![1u8, 2u8], format!("{:08b}{:08b}", 1u8, 2u8))]
    #[case(vec![1u16, 2u16], format!("{:016b}{:016b}", 1u16, 2u16))]
    #[case(vec![1u32, 2u32], format!("{:032b}{:032b}", 1u32, 2u32))]
    #[case(vec![1u64, 2u64], format!("{:064b}{:064b}", 1u64, 2u64))]
    #[case(vec![1u128, 2u128], format!("{:0128b}{:0128b}", 1u128, 2u128))]
    fn test_iter_to_bits<V: ToBitsIter + Clone>(
        #[case] mut values: Vec<V>,
        #[case] expected: impl AsRef<str>,
    ) {
        let msb0_bits = values.clone().into_msb0();
        let mut expected = expected.as_ref().to_bit_vec();

        assert_eq!(msb0_bits, expected);

        // Reverse order of values
        values.reverse();
        // Reverse order of bits, this also reverses the order of the values
        expected.reverse();

        let lsb0_bits = values.into_lsb0();

        assert_eq!(lsb0_bits, expected);
    }
}
