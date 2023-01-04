use crate::error::ValueError as Error;

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
    /// Creates value from LSB0 bit vec
    pub fn new(typ: ValueType, bits: Vec<bool>) -> Result<Self, Error> {
        let value = match typ {
            ValueType::ConstZero if bits.len() == 0 => Value::ConstZero,
            ValueType::ConstOne if bits.len() == 0 => Value::ConstOne,
            ValueType::Bool if bits.len() == 1 => Value::Bool(
                *bits
                    .get(0)
                    .expect("slice with length 1 has no element at index 0"),
            ),
            ValueType::Bits => Value::Bits(bits),
            ValueType::Bytes if bits.len() % 8 == 0 => Value::Bytes(
                bits.chunks_exact(8)
                    .map(|b| {
                        b.iter()
                            .enumerate()
                            .fold(0, |acc, (i, v)| acc | (*v as u8) << i)
                    })
                    .collect(),
            ),
            ValueType::U8 if bits.len() == 8 => Value::U8(
                bits.iter()
                    .enumerate()
                    .fold(0, |acc, (i, v)| acc | (*v as u8) << i),
            ),
            ValueType::U16 if bits.len() == 16 => Value::U16(
                bits.iter()
                    .enumerate()
                    .fold(0, |acc, (i, v)| acc | (*v as u16) << i),
            ),
            ValueType::U32 if bits.len() == 32 => Value::U32(
                bits.iter()
                    .enumerate()
                    .fold(0, |acc, (i, v)| acc | (*v as u32) << i),
            ),
            ValueType::U64 if bits.len() == 64 => Value::U64(
                bits.iter()
                    .enumerate()
                    .fold(0, |acc, (i, v)| acc | (*v as u64) << i),
            ),
            ValueType::U128 if bits.len() == 128 => Value::U128(
                bits.iter()
                    .enumerate()
                    .fold(0, |acc, (i, v)| acc | (*v as u128) << i),
            ),
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

    /// Converts value to bit vector in LSB0 order
    pub fn to_bits(&self) -> Vec<bool> {
        match self {
            Value::ConstZero => vec![false],
            Value::ConstOne => vec![true],
            Value::Bool(v) => vec![*v],
            Value::Bits(v) => v.clone(),
            Value::Bytes(v) => v
                .iter()
                .map(|byte| (0..8).map(|i| (byte >> i & 1) == 1).collect::<Vec<bool>>())
                .flatten()
                .collect(),
            Value::U8(v) => (0..8).map(|i| (v >> i & 1) == 1).collect(),
            Value::U16(v) => (0..16).map(|i| (v >> i & 1) == 1).collect(),
            Value::U32(v) => (0..32).map(|i| (v >> i & 1) == 1).collect(),
            Value::U64(v) => (0..64).map(|i| (v >> i & 1) == 1).collect(),
            Value::U128(v) => (0..128).map(|i| (v >> i & 1) == 1).collect(),
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

    #[rstest]
    #[case(ValueType::ConstZero, vec![], Value::ConstZero)]
    #[case(ValueType::ConstOne, vec![], Value::ConstOne)]
    #[case(ValueType::Bool, vec![false], Value::Bool(false))]
    #[case(ValueType::Bool, vec![true], Value::Bool(true))]
    #[case(ValueType::Bits, vec![false, true], Value::Bits(vec![false, true]))]
    #[case(ValueType::Bytes, vec![false; 8], Value::Bytes(vec![0]))]
    #[case(ValueType::Bytes, vec![true; 8], Value::Bytes(vec![u8::MAX]))]
    #[case(ValueType::U8, vec![false; 8], Value::U8(0u8))]
    #[case(ValueType::U8, vec![true; 8], Value::U8(u8::MAX))]
    #[case(ValueType::U16, vec![false; 16], Value::U16(0u16))]
    #[case(ValueType::U16, vec![true; 16], Value::U16(u16::MAX))]
    #[case(ValueType::U32, vec![false; 32], Value::U32(0u32))]
    #[case(ValueType::U32, vec![true; 32], Value::U32(u32::MAX))]
    #[case(ValueType::U64, vec![false; 64], Value::U64(0u64))]
    #[case(ValueType::U64, vec![true; 64], Value::U64(u64::MAX))]
    #[case(ValueType::U128, vec![false; 128], Value::U128(0u128))]
    #[case(ValueType::U128, vec![true; 128], Value::U128(u128::MAX))]
    fn test_value_new(
        #[case] value_type: ValueType,
        #[case] bits: Vec<bool>,
        #[case] expected: Value,
    ) {
        let value = Value::new(value_type, bits).unwrap();
        assert_eq!(value, expected);
        assert_eq!(value.value_type(), value_type);
    }

    #[rstest]
    #[case(ValueType::Bool, vec![])]
    #[case(ValueType::Bool, vec![false; 2])]
    #[case(ValueType::Bytes, vec![false; 7])]
    #[case(ValueType::Bytes, vec![false; 9])]
    #[case(ValueType::U8, vec![false; 7])]
    #[case(ValueType::U8, vec![false; 9])]
    #[case(ValueType::U16, vec![false; 15])]
    #[case(ValueType::U16, vec![false; 17])]
    #[case(ValueType::U32, vec![false; 31])]
    #[case(ValueType::U32, vec![false; 33])]
    #[case(ValueType::U64, vec![false; 63])]
    #[case(ValueType::U64, vec![false; 65])]
    #[case(ValueType::U128, vec![false; 127])]
    #[case(ValueType::U128, vec![false; 129])]
    fn test_value_new_should_fail(#[case] value_type: ValueType, #[case] bits: Vec<bool>) {
        let err = Value::new(value_type, bits).unwrap_err();
        assert!(matches!(err, Error::ParseError(_, _)))
    }

    #[rstest]
    #[case(ValueType::Bool, false, Value::Bool(false))]
    #[case(ValueType::Bool, true, Value::Bool(true))]
    #[case(ValueType::Bits, vec![false, true], Value::Bits(vec![false, true]))]
    #[case(ValueType::Bytes, vec![0, 1], Value::Bytes(vec![0, 1]))]
    #[case(ValueType::U8, 0u8, Value::U8(0u8))]
    #[case(ValueType::U16, 0u16, Value::U16(0u16))]
    #[case(ValueType::U32, 0u32, Value::U32(0u32))]
    #[case(ValueType::U64, 0u64, Value::U64(0u64))]
    #[case(ValueType::U128, 0u128, Value::U128(0u128))]
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
    #[case(Value::ConstZero, vec![false])]
    #[case(Value::ConstOne, vec![true])]
    #[case(false, vec![false])]
    #[case(true, vec![true])]
    #[case(vec![false, true], vec![false, true])]
    #[case(vec![0, 1], [vec![false; 8], vec![true], vec![false; 7]].concat())]
    #[case(0u8, vec![false; 8])]
    #[case(0u16, vec![false; 16])]
    #[case(0u32, vec![false; 32])]
    #[case(0u64, vec![false; 64])]
    #[case(0u128, vec![false; 128])]
    fn test_value_to_bits(#[case] value: impl Into<Value>, #[case] expected: Vec<bool>) {
        let value: Value = value.into();
        assert_eq!(value.to_bits(), expected);
    }
}
