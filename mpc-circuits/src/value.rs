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
            ValueType::U16 => Value::U16(
                bits.iter()
                    .enumerate()
                    .fold(0, |acc, (i, v)| acc | (*v as u16) << i),
            ),
            ValueType::U32 => Value::U32(
                bits.iter()
                    .enumerate()
                    .fold(0, |acc, (i, v)| acc | (*v as u32) << i),
            ),
            ValueType::U64 => Value::U64(
                bits.iter()
                    .enumerate()
                    .fold(0, |acc, (i, v)| acc | (*v as u64) << i),
            ),
            ValueType::U128 => Value::U128(
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
