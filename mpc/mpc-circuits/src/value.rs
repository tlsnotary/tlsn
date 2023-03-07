use utils::bits::{BitsToBytes, BitsToUint, BytesToBits};

use crate::error::ValueError as Error;

/// The bit order of a string of bits
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BitOrder {
    /// Most significant bit first
    Msb0,
    /// Least significant bit first
    Lsb0,
}

impl BitOrder {
    /// Parses bit order from string
    ///
    /// Returns error if string is not a valid bit order
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "msb0" => Ok(Self::Msb0),
            "lsb0" => Ok(Self::Lsb0),
            _ => Err(s.to_string()),
        }
    }
}

impl ToString for BitOrder {
    fn to_string(&self) -> String {
        match self {
            BitOrder::Msb0 => "Msb0".to_string(),
            BitOrder::Lsb0 => "Lsb0".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    ConstZero,
    ConstOne,
    Bool(bool),
    Bits(Vec<bool>),
    Bytes(Vec<u8>),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
}

impl Value {
    pub fn new(typ: ValueType, bits: Vec<bool>, order: BitOrder) -> Result<Self, Error> {
        match order {
            BitOrder::Msb0 => Self::new_from_msb0(typ, bits),
            BitOrder::Lsb0 => Self::new_from_lsb0(typ, bits),
        }
    }

    /// Creates value from LSB0 bit vec
    fn new_from_lsb0(typ: ValueType, mut bits: Vec<bool>) -> Result<Self, Error> {
        match typ {
            ValueType::Bytes => {
                // Preserve byte-order, but reverse bits in each byte
                bits.chunks_mut(8).for_each(|byte| byte.reverse());
            }
            // Preserve bit-order
            ValueType::Bits => {}
            _ => bits.reverse(),
        }
        Self::new_from_msb0(typ, bits)
    }

    /// Creates value from MSB0 bit vec
    fn new_from_msb0(typ: ValueType, bits: Vec<bool>) -> Result<Self, Error> {
        let value = match typ {
            ValueType::ConstZero if bits.len() == 0 => Value::ConstZero,
            ValueType::ConstOne if bits.len() == 0 => Value::ConstOne,
            ValueType::Bool if bits.len() == 1 => Value::Bool(
                *bits
                    .get(0)
                    .expect("slice with length 1 has no element at index 0"),
            ),
            ValueType::Bits if bits.len() > 0 => Value::Bits(bits),
            ValueType::Bytes if bits.len() % 8 == 0 => Value::Bytes(bits.msb0_into_bytes()),
            ValueType::U8 if bits.len() == 8 => Value::U8(bits.msb0_into_u8()),
            ValueType::U16 if bits.len() == 16 => Value::U16(bits.msb0_into_u16()),
            ValueType::U32 if bits.len() == 32 => Value::U32(bits.msb0_into_u32()),
            ValueType::U64 if bits.len() == 64 => Value::U64(bits.msb0_into_u64()),
            ValueType::U128 if bits.len() == 128 => Value::U128(bits.msb0_into_u128()),
            _ => return Err(Error::ParseError(bits.len(), typ)),
        };
        Ok(value)
    }

    /// Returns type of value
    pub fn value_type(&self) -> ValueType {
        match self {
            Value::ConstZero => ValueType::ConstZero,
            Value::ConstOne => ValueType::ConstOne,
            Value::Bool(_) => ValueType::Bool,
            Value::Bits(_) => ValueType::Bits,
            Value::Bytes(_) => ValueType::Bytes,
            Value::U8(_) => ValueType::U8,
            Value::U16(_) => ValueType::U16,
            Value::U32(_) => ValueType::U32,
            Value::U64(_) => ValueType::U64,
            Value::U128(_) => ValueType::U128,
        }
    }

    /// Returns bit length of value
    pub fn len(&self) -> usize {
        match self {
            Value::ConstZero => 1,
            Value::ConstOne => 1,
            Value::Bool(_) => 1,
            Value::Bits(v) => v.len(),
            Value::Bytes(v) => v.len() * 8,
            Value::U8(_) => 8,
            Value::U16(_) => 16,
            Value::U32(_) => 32,
            Value::U64(_) => 64,
            Value::U128(_) => 128,
        }
    }

    /// Returns value encoded as bit vector in given order
    pub fn to_bits(&self, order: BitOrder) -> Vec<bool> {
        match order {
            BitOrder::Msb0 => self.to_msb0_bits(),
            BitOrder::Lsb0 => self.to_lsb0_bits(),
        }
    }

    /// Converts value to bit vector in LSB0 order
    fn to_lsb0_bits(&self) -> Vec<bool> {
        let mut bits = self.to_msb0_bits();
        match self.value_type() {
            ValueType::Bytes => {
                // Preserve byte-order, but reverse bits in each byte
                bits.chunks_mut(8).for_each(|byte| byte.reverse());
            }
            // Preserve bit-order
            ValueType::Bits => {}
            _ => bits.reverse(),
        }
        bits
    }

    /// Converts value to bit vector in MSB0 order
    fn to_msb0_bits(&self) -> Vec<bool> {
        match self {
            Value::ConstZero => vec![false],
            Value::ConstOne => vec![true],
            Value::Bool(v) => vec![*v],
            Value::Bits(v) => v.clone(),
            Value::Bytes(v) => v.clone().into_msb0(),
            Value::U8(v) => (0..8).rev().map(|i| (v >> i & 1) == 1).collect(),
            Value::U16(v) => (0..16).rev().map(|i| (v >> i & 1) == 1).collect(),
            Value::U32(v) => (0..32).rev().map(|i| (v >> i & 1) == 1).collect(),
            Value::U64(v) => (0..64).rev().map(|i| (v >> i & 1) == 1).collect(),
            Value::U128(v) => (0..128).rev().map(|i| (v >> i & 1) == 1).collect(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ValueType {
    ConstZero,
    ConstOne,
    Bool,
    Bits,
    Bytes,
    U8,
    U16,
    U32,
    U64,
    U128,
}

impl ValueType {
    /// Returns whether value is a constant type
    pub fn is_constant(&self) -> bool {
        matches!(self, ValueType::ConstZero | ValueType::ConstOne)
    }

    pub(crate) fn valid_length(&self, len: usize) -> Result<(), Error> {
        let valid = match *self {
            ValueType::ConstZero | ValueType::ConstOne | ValueType::Bool if len == 1 => true,
            ValueType::Bits if len > 0 => true,
            ValueType::Bytes if (len % 8 == 0) && (len > 0) => true,
            ValueType::U8 if len == 8 => true,
            ValueType::U16 if len == 16 => true,
            ValueType::U32 if len == 32 => true,
            ValueType::U64 if len == 64 => true,
            ValueType::U128 if len == 128 => true,
            _ => false,
        };

        if valid {
            Ok(())
        } else {
            return Err(Error::InvalidLength(*self, len));
        }
    }
}

impl From<bool> for Value {
    fn from(v: bool) -> Self {
        Value::Bool(v)
    }
}

impl From<Vec<bool>> for Value {
    fn from(v: Vec<bool>) -> Self {
        Value::Bits(v)
    }
}

impl From<Vec<u8>> for Value {
    fn from(v: Vec<u8>) -> Self {
        Value::Bytes(v)
    }
}

impl From<u8> for Value {
    fn from(v: u8) -> Self {
        Value::U8(v)
    }
}

impl From<u16> for Value {
    fn from(v: u16) -> Self {
        Value::U16(v)
    }
}

impl From<u32> for Value {
    fn from(v: u32) -> Self {
        Value::U32(v)
    }
}

impl From<u64> for Value {
    fn from(v: u64) -> Self {
        Value::U64(v)
    }
}

impl From<u128> for Value {
    fn from(v: u128) -> Self {
        Value::U128(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;

    use utils::bits::BitStringToBoolVec;

    #[rstest]
    #[case::const_0(ValueType::ConstZero, "", Value::ConstZero)]
    #[case::const_1(ValueType::ConstOne, "", Value::ConstOne)]
    #[case::bool_0(ValueType::Bool, "0", Value::Bool(false))]
    #[case::bool_1(ValueType::Bool, "1", Value::Bool(true))]
    #[case::bits_1(ValueType::Bits, "01", Value::Bits(vec![false, true]))]
    #[case::bytes_1(ValueType::Bytes, "00000000", Value::Bytes(vec![0]))]
    #[case::bytes_2(ValueType::Bytes, "0000000000000001", Value::Bytes(vec![0,1]))]
    #[case::u8(ValueType::U8, "00000001", Value::U8(1u8))]
    #[case::u16(ValueType::U16, format!("{:016b}", 1u16), Value::U16(1u16))]
    #[case::u32(ValueType::U32, format!("{:032b}", 1u32), Value::U32(1u32))]
    #[case::u64(ValueType::U64, format!("{:064b}", 1u64), Value::U64(1u64))]
    #[case::u128(ValueType::U128, format!("{:0128b}", 1u128), Value::U128(1u128))]
    fn test_value_new(
        #[case] value_type: ValueType,
        #[case] bits: impl AsRef<str>,
        #[case] expected: Value,
    ) {
        let value = Value::new_from_msb0(value_type, bits.as_ref().to_bool_vec()).unwrap();
        assert_eq!(value, expected);
        assert_eq!(value.value_type(), value_type);
    }

    #[rstest]
    #[case::const_zero(ValueType::ConstZero, "1")]
    #[case::const_one(ValueType::ConstOne, "0")]
    #[case::bool_empty(ValueType::Bool, "")]
    #[case::bool_extra_bits(ValueType::Bool, "11")]
    #[case::bits_empty(ValueType::Bits, "")]
    #[case::bytes_7bits(ValueType::Bytes, "0000000")]
    #[case::bytes_9bits(ValueType::Bytes, "000000001")]
    #[case::u8_7bit(ValueType::U8, format!("{:07b}", 1u8))]
    #[case::u16_15bit(ValueType::U16, format!("{:015b}", 1u16))]
    #[case::u32_31bit(ValueType::U32, format!("{:031b}", 1u32))]
    #[case::u64_63bit(ValueType::U64, format!("{:063b}", 1u64))]
    #[case::u128_127bit(ValueType::U128, format!("{:0127b}", 1u128))]
    fn test_value_wrong_bit_length(#[case] value_type: ValueType, #[case] bits: impl AsRef<str>) {
        let err = Value::new_from_msb0(value_type, bits.as_ref().to_bool_vec()).unwrap_err();
        assert!(matches!(err, Error::ParseError(_, _)))
    }

    #[rstest]
    #[case::bool_false(ValueType::Bool, false, Value::Bool(false))]
    #[case::bool_true(ValueType::Bool, true, Value::Bool(true))]
    #[case::bits(ValueType::Bits, vec![false, true], Value::Bits(vec![false, true]))]
    #[case::bytes(ValueType::Bytes, vec![0, 1], Value::Bytes(vec![0, 1]))]
    #[case::u8(ValueType::U8, 0u8, Value::U8(0u8))]
    #[case::u16(ValueType::U16, 0u16, Value::U16(0u16))]
    #[case::u32(ValueType::U32, 0u32, Value::U32(0u32))]
    #[case::u64(ValueType::U64, 0u64, Value::U64(0u64))]
    #[case::u128(ValueType::U128, 0u128, Value::U128(0u128))]
    fn test_value_into(
        #[case] value_type: ValueType,
        #[case] value: impl Into<Value>,
        #[case] expected: Value,
    ) {
        let value: Value = value.into();
        assert_eq!(value, expected);
        assert_eq!(value.value_type(), value_type);
    }

    #[rstest]
    #[case::const_0(Value::ConstZero, "0")]
    #[case::const_1(Value::ConstOne, "1")]
    #[case::bool_false(false, "0")]
    #[case::bool_true(true, "1")]
    #[case::bits(vec![false, true], "01")]
    #[case::bytes(vec![0, 1], "0000000000000001")]
    #[case::u8(1u8, "00000001")]
    #[case::u16(1u16, format!("{:016b}", 1u16))]
    #[case::u32(1u32, format!("{:032b}", 1u32))]
    #[case::u64(1u64, format!("{:064b}", 1u64))]
    #[case::u128(1u128, format!("{:0128b}", 1u128))]
    fn test_value_to_bits(#[case] value: impl Into<Value>, #[case] expected: impl AsRef<str>) {
        let value: Value = value.into();
        assert_eq!(value.to_msb0_bits(), expected.to_bool_vec());
    }
}
