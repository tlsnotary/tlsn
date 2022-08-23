use crate::error::ValueError as Error;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Bool(bool),
    Bits(Vec<bool>),
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
            ValueType::Bool if bits.len() == 1 => Value::Bool(
                *bits
                    .get(0)
                    .expect("slice with length 1 has no element at index 0"),
            ),
            ValueType::Bits => Value::Bits(bits),
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
            _ => return Err(Error::InvalidValue(typ, bits.to_vec())),
        };
        Ok(value)
    }

    /// Returns type of value
    pub fn value_type(&self) -> ValueType {
        match self {
            Value::Bool(_) => ValueType::Bool,
            Value::Bits(_) => ValueType::Bits,
            Value::U8(_) => ValueType::U8,
            Value::U16(_) => ValueType::U16,
            Value::U32(_) => ValueType::U32,
            Value::U64(_) => ValueType::U64,
            Value::U128(_) => ValueType::U128,
        }
    }

    /// Converts value to bit vector in LSB0 order
    pub fn to_bits(&self) -> Vec<bool> {
        match self {
            Value::Bool(v) => vec![*v],
            Value::Bits(v) => v.clone(),
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
    Bool,
    Bits,
    U8,
    U16,
    U32,
    U64,
    U128,
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
