use std::marker::PhantomData;

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

/// Helper trait for converting bit strings to bool iterators.
pub trait BitStringToBoolVec<'a> {
    /// Converts a bit string to an iterator of bools.
    ///
    /// Panics if the string contains characters other than '0' or '1'.
    fn to_bool_iter(&'a self) -> BitStringIterator<'a>;

    /// Converts a bit string to a bool vec.
    ///
    /// Panics if the string contains characters other than '0' or '1'.
    fn to_bool_vec(&'a self) -> Vec<bool> {
        self.to_bool_iter().collect()
    }
}

impl<'a, T> BitStringToBoolVec<'a> for T
where
    T: AsRef<str>,
{
    fn to_bool_iter(&'a self) -> BitStringIterator<'a> {
        BitStringIterator {
            string: self.as_ref(),
            pos: 0,
        }
    }
}

pub struct Lsb0;
pub struct Msb0;

pub struct ByteIterator<I, Ord>
where
    I: Iterator<Item = bool> + ?Sized,
{
    bit_order: PhantomData<Ord>,
    bit_iter: I,
}

impl<I> Iterator for ByteIterator<I, Lsb0>
where
    I: Iterator<Item = bool>,
{
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        let mut byte = 0u8;
        for idx in 0u8..8 {
            let Some(bit) = self.bit_iter.next() else {
                if idx == 0 {
                    // We've reached the end of the bit iterator
                    return None;
                } else {
                    panic!("bit iterator yielded less than a byte")
                }
            };
            byte ^= (bit as u8) << idx;
        }

        Some(byte)
    }
}

impl<I> Iterator for ByteIterator<I, Msb0>
where
    I: Iterator<Item = bool>,
{
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        let mut byte = 0u8;
        for idx in 0u8..8 {
            let Some(bit) = self.bit_iter.next() else {
                if idx == 0 {
                    // We've reached the end of the bit iterator
                    return None;
                } else {
                    panic!("bit iterator yielded less than a byte")
                }
            };
            byte ^= (bit as u8) << (7 - idx);
        }

        Some(byte)
    }
}

/// Helper trait used for converting bool iterators into byte iterators.
pub trait BitsToBytes
where
    Self: IntoIterator<Item = bool>,
{
    /// Converts an iterator of LSB0 bits into an iterator of bytes.
    ///
    /// Panics if number of bits is not a multiple of 8.
    fn lsb0_into_bytes_iter(self) -> ByteIterator<<Self as IntoIterator>::IntoIter, Lsb0>;

    /// Converts an iterator of LSB0 bits into a byte vector.
    ///
    /// Panics if number of bits is not a multiple of 8.
    fn lsb0_into_bytes(self) -> Vec<u8>;

    /// Converts an iterator of MSB0 bits into an iterator of bytes.
    ///
    /// Panics if number of bits is not a multiple of 8.
    fn msb0_into_bytes_iter(self) -> ByteIterator<<Self as IntoIterator>::IntoIter, Msb0>;

    /// Converts an iterator of MSB0 bits into a byte vector.
    ///
    /// Panics if number of bits is not a multiple of 8.
    fn msb0_into_bytes(self) -> Vec<u8>;
}

impl<I> BitsToBytes for I
where
    I: IntoIterator<Item = bool>,
{
    fn lsb0_into_bytes_iter(self) -> ByteIterator<<Self as IntoIterator>::IntoIter, Lsb0> {
        ByteIterator {
            bit_order: PhantomData::<Lsb0>,
            bit_iter: self.into_iter(),
        }
    }

    fn lsb0_into_bytes(self) -> Vec<u8> {
        self.lsb0_into_bytes_iter().collect()
    }

    fn msb0_into_bytes_iter(self) -> ByteIterator<<Self as IntoIterator>::IntoIter, Msb0> {
        ByteIterator {
            bit_order: PhantomData::<Msb0>,
            bit_iter: self.into_iter(),
        }
    }

    fn msb0_into_bytes(self) -> Vec<u8> {
        self.msb0_into_bytes_iter().collect()
    }
}

pub struct BitIterator<I, Ord>
where
    I: Iterator<Item = u8> + ?Sized,
{
    bit_order: PhantomData<Ord>,
    bit_idx: usize,
    byte: Option<u8>,
    byte_iter: I,
}

impl<I> Iterator for BitIterator<I, Lsb0>
where
    I: Iterator<Item = u8>,
{
    type Item = bool;

    fn next(&mut self) -> Option<Self::Item> {
        if self.bit_idx == 0 {
            self.byte = self.byte_iter.next();
        }

        let byte = self.byte?;

        let bit = (byte >> self.bit_idx) & 1 == 1;

        self.bit_idx += 1;

        if self.bit_idx == 8 {
            self.bit_idx = 0;
        }

        Some(bit)
    }
}

impl<I> Iterator for BitIterator<I, Msb0>
where
    I: Iterator<Item = u8>,
{
    type Item = bool;

    fn next(&mut self) -> Option<Self::Item> {
        if self.bit_idx == 0 {
            self.byte = self.byte_iter.next();
        }

        let byte = self.byte?;

        let bit = (byte >> (7 - self.bit_idx)) & 1 == 1;

        self.bit_idx += 1;

        if self.bit_idx == 8 {
            self.bit_idx = 0;
        }

        Some(bit)
    }
}

/// Helper trait for converting an iterator of bytes to an iterator of bits
pub trait BytesToBits
where
    Self: IntoIterator<Item = u8>,
{
    /// Converts an iterator of bytes into an iterator of LSB0 bits.
    fn into_lsb0_iter(self) -> BitIterator<<Self as IntoIterator>::IntoIter, Lsb0>;

    /// Converts an iterator of bytes into an LSB0 bit vector.
    fn into_lsb0(self) -> Vec<bool>;

    /// Converts an iterator of bytes into an iterator of MSB0 bits.
    fn into_msb0_iter(self) -> BitIterator<<Self as IntoIterator>::IntoIter, Msb0>;

    /// Converts an iterator of bytes into an MSB0 bit vector.
    fn into_msb0(self) -> Vec<bool>;
}

impl<T> BytesToBits for T
where
    T: IntoIterator<Item = u8>,
{
    fn into_lsb0_iter(self) -> BitIterator<<Self as IntoIterator>::IntoIter, Lsb0> {
        BitIterator {
            bit_order: PhantomData::<Lsb0>,
            bit_idx: 0,
            byte: None,
            byte_iter: self.into_iter(),
        }
    }

    fn into_lsb0(self) -> Vec<bool> {
        self.into_lsb0_iter().collect()
    }

    fn into_msb0_iter(self) -> BitIterator<<Self as IntoIterator>::IntoIter, Msb0> {
        BitIterator {
            bit_order: PhantomData::<Msb0>,
            bit_idx: 0,
            byte: None,
            byte_iter: self.into_iter(),
        }
    }

    fn into_msb0(self) -> Vec<bool> {
        self.into_msb0_iter().collect()
    }
}

/// Helper trait for converting an iterator of bits to an unsigned integer.
pub trait BitsToUint {
    /// Converts an iterator of LSB0 bits into a u8.
    ///
    /// Panics if number of bits is not 8.
    fn lsb0_into_u8(self) -> u8;

    /// Converts an iterator of LSB0 bits into a u16.
    ///
    /// Panics if number of bits is not 16.
    fn lsb0_into_u16(self) -> u16;

    /// Converts an iterator of LSB0 bits into a u32.
    ///
    /// Panics if number of bits is not 32.
    fn lsb0_into_u32(self) -> u32;

    /// Converts an iterator of LSB0 bits into a u64.
    ///
    /// Panics if number of bits is not 64.
    fn lsb0_into_u64(self) -> u64;

    /// Converts an iterator of LSB0 bits into a u128.
    ///
    /// Panics if number of bits is not 128.
    fn lsb0_into_u128(self) -> u128;

    /// Converts an iterator of MSB0 bits into a u8.
    ///
    /// Panics if number of bits is not 8.
    fn msb0_into_u8(self) -> u8;

    /// Converts an iterator of MSB0 bits into a u16.
    ///
    /// Panics if number of bits is not 16.
    fn msb0_into_u16(self) -> u16;

    /// Converts an iterator of MSB0 bits into a u32.
    ///
    /// Panics if number of bits is not 32.
    fn msb0_into_u32(self) -> u32;

    /// Converts an iterator of MSB0 bits into a u64.
    ///
    /// Panics if number of bits is not 64.
    fn msb0_into_u64(self) -> u64;

    /// Converts an iterator of MSB0 bits into a u128.
    ///
    /// Panics if number of bits is not 128.
    fn msb0_into_u128(self) -> u128;
}

impl<T> BitsToUint for T
where
    T: IntoIterator<Item = bool>,
{
    fn lsb0_into_u8(self) -> u8 {
        let mut iter = self.into_iter();

        let mut value = 0u8;

        for i in 0..8 {
            let Some(bit) = iter.next() else {
                panic!("Not enough bits to convert to u8");
            };

            value |= (bit as u8) << i;
        }

        value
    }

    fn lsb0_into_u16(self) -> u16 {
        let mut iter = self.into_iter();

        let mut value = 0u16;

        for i in 0..16 {
            let Some(bit) = iter.next() else {
                panic!("Not enough bits to convert to u16");
            };

            value |= (bit as u16) << i;
        }

        value
    }

    fn lsb0_into_u32(self) -> u32 {
        let mut iter = self.into_iter();

        let mut value = 0u32;

        for i in 0..32 {
            let Some(bit) = iter.next() else {
                panic!("Not enough bits to convert to u32");
            };

            value |= (bit as u32) << i;
        }

        value
    }

    fn lsb0_into_u64(self) -> u64 {
        let mut iter = self.into_iter();

        let mut value = 0u64;

        for i in 0..64 {
            let Some(bit) = iter.next() else {
                panic!("Not enough bits to convert to u64");
            };

            value |= (bit as u64) << i;
        }

        value
    }

    fn lsb0_into_u128(self) -> u128 {
        let mut iter = self.into_iter();

        let mut value = 0u128;

        for i in 0..128 {
            let Some(bit) = iter.next() else {
                panic!("Not enough bits to convert to u128");
            };

            value |= (bit as u128) << i;
        }

        value
    }

    fn msb0_into_u8(self) -> u8 {
        let mut iter = self.into_iter();

        let mut value = 0u8;

        for i in 0..8 {
            let Some(bit) = iter.next() else {
                panic!("Not enough bits to convert to u8");
            };

            value |= (bit as u8) << (7 - i);
        }

        value
    }

    fn msb0_into_u16(self) -> u16 {
        let mut iter = self.into_iter();

        let mut value = 0u16;

        for i in 0..16 {
            let Some(bit) = iter.next() else {
                panic!("Not enough bits to convert to u16");
            };

            value |= (bit as u16) << (15 - i);
        }

        value
    }

    fn msb0_into_u32(self) -> u32 {
        let mut iter = self.into_iter();

        let mut value = 0u32;

        for i in 0..32 {
            let Some(bit) = iter.next() else {
                panic!("Not enough bits to convert to u32");
            };

            value |= (bit as u32) << (31 - i);
        }

        value
    }

    fn msb0_into_u64(self) -> u64 {
        let mut iter = self.into_iter();

        let mut value = 0u64;

        for i in 0..64 {
            let Some(bit) = iter.next() else {
                panic!("Not enough bits to convert to u64");
            };

            value |= (bit as u64) << (63 - i);
        }

        value
    }

    fn msb0_into_u128(self) -> u128 {
        let mut iter = self.into_iter();

        let mut value = 0u128;

        for i in 0..128 {
            let Some(bit) = iter.next() else {
                panic!("Not enough bits to convert to u128");
            };

            value |= (bit as u128) << (127 - i);
        }

        value
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
        let bits: Vec<bool> = bits.to_bool_vec();

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
        let bytes: Vec<u8> = bits.to_bool_iter().lsb0_into_bytes();

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
        let bytes: Vec<u8> = bits.to_bool_iter().msb0_into_bytes();

        assert_eq!(bytes, expected);
    }

    #[rstest]
    #[case::single_byte_1(vec![1u8], "10000000")]
    #[case::single_byte_0(vec![0u8], "00000000")]
    #[case::single_byte_255(vec![255u8], "11111111")]
    #[case::multi_byte(vec![0u8, 1u8], "0000000010000000")]
    #[case::empty(vec![], "")]
    fn test_bytes_to_lsb0(#[case] bytes: Vec<u8>, #[case] expected: &str) {
        let expected = expected.to_bool_vec();

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
        let expected = expected.to_bool_vec();

        let bits: Vec<bool> = bytes.into_msb0();

        assert_eq!(bits, expected);
    }

    #[rstest]
    #[case(format!("{:08b}", 0u8), 0u8)]
    #[case(format!("{:08b}", 1u8), 1u8)]
    #[case(format!("{:08b}", u8::MAX), u8::MAX)]
    fn test_lsb0_to_u8(#[case] bits: impl AsRef<str>, #[case] expected: u8) {
        let msb_value = bits.to_bool_iter().msb0_into_u8();

        let lsb_bits = bits.as_ref().chars().rev().collect::<String>();
        let lsb_value = lsb_bits.to_bool_iter().lsb0_into_u8();

        assert_eq!(msb_value, expected);
        assert_eq!(lsb_value, expected);
    }

    #[rstest]
    #[case(format!("{:016b}", 0u16), 0u16)]
    #[case(format!("{:016b}", 1u16), 1u16)]
    #[case(format!("{:016b}", u16::MAX), u16::MAX)]
    fn test_lsb0_to_u16(#[case] bits: impl AsRef<str>, #[case] expected: u16) {
        let msb_value = bits.to_bool_iter().msb0_into_u16();

        let lsb_bits = bits.as_ref().chars().rev().collect::<String>();
        let lsb_value = lsb_bits.to_bool_iter().lsb0_into_u16();

        assert_eq!(msb_value, expected);
        assert_eq!(lsb_value, expected);
    }

    #[rstest]
    #[case(format!("{:032b}", 0u32), 0u32)]
    #[case(format!("{:032b}", 1u32), 1u32)]
    #[case(format!("{:032b}", u32::MAX), u32::MAX)]
    fn test_lsb0_to_u32(#[case] bits: impl AsRef<str>, #[case] expected: u32) {
        let msb_value = bits.to_bool_iter().msb0_into_u32();

        let lsb_bits = bits.as_ref().chars().rev().collect::<String>();
        let lsb_value = lsb_bits.to_bool_iter().lsb0_into_u32();

        assert_eq!(msb_value, expected);
        assert_eq!(lsb_value, expected);
    }

    #[rstest]
    #[case(format!("{:064b}", 0u64), 0u64)]
    #[case(format!("{:064b}", 1u64), 1u64)]
    #[case(format!("{:064b}", u64::MAX), u64::MAX)]
    fn test_lsb0_to_u64(#[case] bits: impl AsRef<str>, #[case] expected: u64) {
        let msb_value = bits.to_bool_iter().msb0_into_u64();

        let lsb_bits = bits.as_ref().chars().rev().collect::<String>();
        let lsb_value = lsb_bits.to_bool_iter().lsb0_into_u64();

        assert_eq!(msb_value, expected);
        assert_eq!(lsb_value, expected);
    }

    #[rstest]
    #[case(format!("{:0128b}", 0u128), 0u128)]
    #[case(format!("{:0128b}", 1u128), 1u128)]
    #[case(format!("{:0128b}", u128::MAX), u128::MAX)]
    fn test_lsb0_to_u128(#[case] bits: impl AsRef<str>, #[case] expected: u128) {
        let msb_value = bits.to_bool_iter().msb0_into_u128();

        let lsb_bits = bits.as_ref().chars().rev().collect::<String>();
        let lsb_value = lsb_bits.to_bool_iter().lsb0_into_u128();

        assert_eq!(msb_value, expected);
        assert_eq!(lsb_value, expected);
    }
}
