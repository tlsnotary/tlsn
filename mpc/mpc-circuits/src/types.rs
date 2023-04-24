//! Types for encoding other types as binary values.

use std::{
    fmt::{self, Display, Formatter},
    ops::Index,
};

use crate::components::{Feed, Node};
use utils::bits::{FromBits, ToBits, ToBitsIter};

/// An error related to binary type conversions.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum TypeError {
    #[error("Invalid binary representation length: expected: {expected}, actual: {actual}")]
    InvalidLength { expected: usize, actual: usize },
    #[error("Unexpected type, expected: {expected}, actual: {actual}")]
    UnexpectedType {
        expected: ValueType,
        actual: ValueType,
    },
}

/// A type that can be represented in binary form.
#[allow(clippy::len_without_is_empty)]
pub trait ToBinaryRepr: ToBitsIter + Into<Value> {
    /// The binary representation of the type.
    type Repr: Clone + Into<BinaryRepr>;

    /// The length of the type in bits.
    fn len(&self) -> usize;

    /// Creates new binary representation of the type.
    fn new_bin_repr(nodes: &[Node<Feed>]) -> Result<Self::Repr, TypeError>;
}

/// A type for which the value type can be statically determined.
pub trait StaticValueType: Into<Value> {
    /// The value type of the type.
    fn value_type() -> ValueType;
}

/// A type that has a constant bit length.
pub trait BinaryLength {
    /// The length of the type in bits.
    const LEN: usize;
}

/// A binary representation of a type.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
#[allow(clippy::large_enum_variant, missing_docs)]
pub enum BinaryRepr {
    Bit(Bit),
    U8(U8),
    U16(U16),
    U32(U32),
    U64(U64),
    U128(U128),
    Array(Vec<BinaryRepr>),
}

impl BinaryRepr {
    /// Returns the type of the value.
    pub fn value_type(&self) -> ValueType {
        match self {
            BinaryRepr::Bit(_) => ValueType::Bit,
            BinaryRepr::U8(_) => ValueType::U8,
            BinaryRepr::U16(_) => ValueType::U16,
            BinaryRepr::U32(_) => ValueType::U32,
            BinaryRepr::U64(_) => ValueType::U64,
            BinaryRepr::U128(_) => ValueType::U128,
            BinaryRepr::Array(v) => ValueType::Array(Box::new(v[0].value_type()), v.len()),
        }
    }

    /// Returns the length of the type in bits.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        match self {
            BinaryRepr::Bit(Bit { .. }) => 1,
            BinaryRepr::U8(U8 { .. }) => 8,
            BinaryRepr::U16(U16 { .. }) => 16,
            BinaryRepr::U32(U32 { .. }) => 32,
            BinaryRepr::U64(U64 { .. }) => 64,
            BinaryRepr::U128(U128 { .. }) => 128,
            BinaryRepr::Array(v) => v.iter().map(|v| v.len()).sum(),
        }
    }

    /// Returns an iterator over the nodes.
    pub fn iter(&self) -> Box<dyn Iterator<Item = &Node<Feed>> + '_> {
        match self {
            BinaryRepr::Bit(v) => Box::new(v.0.iter()),
            BinaryRepr::U8(v) => Box::new(v.0.iter()),
            BinaryRepr::U16(v) => Box::new(v.0.iter()),
            BinaryRepr::U32(v) => Box::new(v.0.iter()),
            BinaryRepr::U64(v) => Box::new(v.0.iter()),
            BinaryRepr::U128(v) => Box::new(v.0.iter()),
            BinaryRepr::Array(v) => Box::new(v.iter().flat_map(|v| v.iter())),
        }
    }

    /// Returns a mutable iterator over the nodes.
    pub(crate) fn iter_mut(&mut self) -> Box<dyn Iterator<Item = &mut Node<Feed>> + '_> {
        match self {
            BinaryRepr::Bit(v) => Box::new(v.0.iter_mut()),
            BinaryRepr::U8(v) => Box::new(v.0.iter_mut()),
            BinaryRepr::U16(v) => Box::new(v.0.iter_mut()),
            BinaryRepr::U32(v) => Box::new(v.0.iter_mut()),
            BinaryRepr::U64(v) => Box::new(v.0.iter_mut()),
            BinaryRepr::U128(v) => Box::new(v.0.iter_mut()),
            BinaryRepr::Array(v) => Box::new(v.iter_mut().flat_map(|v| v.iter_mut())),
        }
    }

    /// Shifts the nodes IDs to the left by the given offset.
    pub(crate) fn shift_left(&mut self, offset: usize) {
        match self {
            BinaryRepr::Bit(v) => v.shift_left(offset),
            BinaryRepr::U8(v) => v.shift_left(offset),
            BinaryRepr::U16(v) => v.shift_left(offset),
            BinaryRepr::U32(v) => v.shift_left(offset),
            BinaryRepr::U64(v) => v.shift_left(offset),
            BinaryRepr::U128(v) => v.shift_left(offset),
            BinaryRepr::Array(v) => v.iter_mut().for_each(|v| v.shift_left(offset)),
        }
    }

    /// Decodes the type from a binary value.
    ///
    /// # Arguments
    ///
    /// * `bits` - The bit representation of the type.
    ///
    /// # Returns
    ///
    /// The decoded value.
    pub fn from_bin_repr(&self, bits: &[bool]) -> Result<Value, TypeError> {
        if bits.len() != self.len() {
            return Err(TypeError::InvalidLength {
                expected: self.len(),
                actual: bits.len(),
            });
        }
        match self {
            BinaryRepr::Bit(_) => Ok(Value::Bit(bits[0])),
            BinaryRepr::U8(_) => Ok(Value::U8(u8::from_lsb0(bits.iter().copied()))),
            BinaryRepr::U16(_) => Ok(Value::U16(u16::from_lsb0(bits.iter().copied()))),
            BinaryRepr::U32(_) => Ok(Value::U32(u32::from_lsb0(bits.iter().copied()))),
            BinaryRepr::U64(_) => Ok(Value::U64(u64::from_lsb0(bits.iter().copied()))),
            BinaryRepr::U128(_) => Ok(Value::U128(u128::from_lsb0(bits.iter().copied()))),
            BinaryRepr::Array(v) => Ok(Value::Array(
                v.iter()
                    .zip(bits.chunks(v[0].len()))
                    .map(|(v, bits)| v.from_bin_repr(bits).unwrap())
                    .collect(),
            )),
        }
    }
}

impl Display for BinaryRepr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            BinaryRepr::Bit(v) => write!(f, "Bit({:?})", v.0),
            BinaryRepr::U8(v) => write!(f, "U8({:?})", v.0),
            BinaryRepr::U16(v) => write!(f, "U16({:?})", v.0),
            BinaryRepr::U32(v) => write!(f, "U32({:?})", v.0),
            BinaryRepr::U64(v) => write!(f, "U64({:?})", v.0),
            BinaryRepr::U128(v) => write!(f, "U128({:?})", v.0),
            BinaryRepr::Array(v) => write!(f, "Array({:?})", v),
        }
    }
}

macro_rules! define_binary_value {
    ($ty:ty, $id:ident, $len:expr) => {
        #[derive(Debug, Clone, Copy)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        #[allow(missing_docs)]
        pub struct $id(
            #[cfg_attr(feature = "serde", serde(with = "serde_arrays"))] [Node<Feed>; $len],
        );

        impl $id {
            pub(crate) fn new(nodes: [Node<Feed>; $len]) -> Self {
                $id(nodes)
            }

            pub(crate) fn nodes(&self) -> [Node<Feed>; $len] {
                self.0
            }

            pub(crate) fn shift_left(&mut self, offset: usize) {
                self.0.iter_mut().for_each(|v| v.shift_left(offset))
            }
        }

        impl ToBinaryRepr for $ty {
            type Repr = $id;

            fn len(&self) -> usize {
                $len
            }

            fn new_bin_repr(nodes: &[Node<Feed>]) -> Result<$id, TypeError> {
                let nodes: [Node<Feed>; $len] =
                    nodes.try_into().map_err(|_| TypeError::InvalidLength {
                        expected: $len,
                        actual: nodes.len(),
                    })?;
                Ok($id::new(nodes))
            }
        }

        impl BinaryLength for $ty {
            const LEN: usize = $len;
        }

        impl<const N: usize> BinaryLength for [$ty; N] {
            const LEN: usize = $len * N;
        }

        impl<const N: usize> ToBinaryRepr for [$ty; N] {
            type Repr = [$id; N];

            fn len(&self) -> usize {
                $len * N
            }

            fn new_bin_repr(nodes: &[Node<Feed>]) -> Result<[$id; N], TypeError> {
                if nodes.len() != $len * N {
                    return Err(TypeError::InvalidLength {
                        expected: $len * N,
                        actual: nodes.len(),
                    });
                }

                Ok(std::array::from_fn(|i| {
                    $id(nodes[i * $len..(i + 1) * $len].try_into().unwrap())
                }))
            }
        }

        impl ToBinaryRepr for Vec<$ty> {
            type Repr = Vec<$id>;

            fn len(&self) -> usize {
                self.len() * $len
            }

            #[allow(clippy::modulo_one)]
            fn new_bin_repr(nodes: &[Node<Feed>]) -> Result<Vec<$id>, TypeError> {
                // nearest rounded up length
                let expected_len = nodes.len() / $len + (nodes.len() % $len != 0) as usize;
                if nodes.len() != expected_len {
                    return Err(TypeError::InvalidLength {
                        expected: expected_len,
                        actual: nodes.len(),
                    });
                }

                let values: Vec<$id> = nodes
                    .chunks($len)
                    .map(|nodes| $id(nodes.try_into().unwrap()))
                    .collect();

                Ok(values)
            }
        }

        impl AsRef<[Node<Feed>]> for $id {
            fn as_ref(&self) -> &[Node<Feed>] {
                &self.0
            }
        }

        impl AsMut<[Node<Feed>]> for $id {
            fn as_mut(&mut self) -> &mut [Node<Feed>] {
                &mut self.0
            }
        }

        impl Index<usize> for $id {
            type Output = Node<Feed>;

            fn index(&self, index: usize) -> &Self::Output {
                &self.0[index]
            }
        }

        impl From<$ty> for Value {
            fn from(v: $ty) -> Self {
                Self::$id(v)
            }
        }

        impl<const N: usize> From<[$ty; N]> for Value {
            fn from(v: [$ty; N]) -> Self {
                Self::Array(v.into_iter().map(|v| v.into()).collect())
            }
        }

        impl From<Vec<$ty>> for Value {
            fn from(v: Vec<$ty>) -> Self {
                Self::Array(v.into_iter().map(|v| v.into()).collect())
            }
        }

        impl TryFrom<Value> for $ty {
            type Error = TypeError;

            fn try_from(value: Value) -> Result<Self, Self::Error> {
                match value {
                    Value::$id(v) => Ok(v),
                    v => Err(TypeError::UnexpectedType {
                        expected: ValueType::$id,
                        actual: v.value_type(),
                    }),
                }
            }
        }

        impl<const N: usize> TryFrom<Value> for [$ty; N] {
            type Error = TypeError;

            fn try_from(value: Value) -> Result<Self, Self::Error> {
                match value {
                    Value::Array(v) => {
                        let mut values = [<$ty>::default(); N];
                        for (i, v) in v.into_iter().enumerate() {
                            values[i] = v.try_into()?;
                        }
                        Ok(values)
                    }
                    v => Err(TypeError::UnexpectedType {
                        expected: ValueType::Array(Box::new(ValueType::$id), N),
                        actual: v.value_type(),
                    }),
                }
            }
        }

        impl TryFrom<Value> for Vec<$ty> {
            type Error = TypeError;

            fn try_from(value: Value) -> Result<Self, Self::Error> {
                match value {
                    Value::Array(v) => Ok(v
                        .into_iter()
                        .map(|v| v.try_into())
                        .collect::<Result<Vec<_>, _>>()?),
                    v => Err(TypeError::UnexpectedType {
                        expected: ValueType::Array(Box::new(ValueType::$id), 0),
                        actual: v.value_type(),
                    }),
                }
            }
        }

        impl From<$id> for BinaryRepr {
            fn from(v: $id) -> Self {
                BinaryRepr::$id(v)
            }
        }

        impl<const N: usize> From<[$id; N]> for BinaryRepr {
            fn from(v: [$id; N]) -> Self {
                BinaryRepr::Array(v.into_iter().map(|v| v.into()).collect())
            }
        }

        impl From<Vec<$id>> for BinaryRepr {
            fn from(v: Vec<$id>) -> Self {
                BinaryRepr::Array(v.into_iter().map(|v| v.into()).collect())
            }
        }

        impl TryFrom<BinaryRepr> for $id {
            type Error = TypeError;

            fn try_from(value: BinaryRepr) -> Result<Self, Self::Error> {
                match value {
                    BinaryRepr::$id(v) => Ok(v),
                    v => Err(TypeError::UnexpectedType {
                        expected: ValueType::$id,
                        actual: v.value_type(),
                    }),
                }
            }
        }
    };
}

define_binary_value!(bool, Bit, 1);
define_binary_value!(u8, U8, 8);
define_binary_value!(u16, U16, 16);
define_binary_value!(u32, U32, 32);
define_binary_value!(u64, U64, 64);
define_binary_value!(u128, U128, 128);

/// A value type that can be encoded into a binary representation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum ValueType {
    Bit,
    U8,
    U16,
    U32,
    U64,
    U128,
    Array(Box<ValueType>, usize),
}

impl ValueType {
    /// Creates a new value type.
    pub fn new<T: StaticValueType>() -> Self {
        T::value_type()
    }

    /// Creates a new array value type.
    pub fn new_array<T: StaticValueType>(len: usize) -> Self {
        ValueType::Array(Box::new(T::value_type()), len)
    }

    /// Returns the length of the value type in bits.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        match self {
            ValueType::Bit => 1,
            ValueType::U8 => 8,
            ValueType::U16 => 16,
            ValueType::U32 => 32,
            ValueType::U64 => 64,
            ValueType::U128 => 128,
            ValueType::Array(ty, len) => ty.len() * len,
        }
    }

    /// Returns whether the value type is an array.
    pub fn is_array(&self) -> bool {
        matches!(self, ValueType::Array(..))
    }

    pub(crate) fn to_bin_repr(&self, nodes: &[Node<Feed>]) -> Result<BinaryRepr, TypeError> {
        if nodes.len() != self.len() {
            return Err(TypeError::InvalidLength {
                expected: self.len(),
                actual: nodes.len(),
            });
        }
        let encoded = match self {
            ValueType::Bit => BinaryRepr::Bit(Bit::new(nodes.try_into().unwrap())),
            ValueType::U8 => BinaryRepr::U8(U8::new(nodes.try_into().unwrap())),
            ValueType::U16 => BinaryRepr::U16(U16::new(nodes.try_into().unwrap())),
            ValueType::U32 => BinaryRepr::U32(U32::new(nodes.try_into().unwrap())),
            ValueType::U64 => BinaryRepr::U64(U64::new(nodes.try_into().unwrap())),
            ValueType::U128 => BinaryRepr::U128(U128::new(nodes.try_into().unwrap())),
            ValueType::Array(ty, _) => BinaryRepr::Array(
                nodes
                    .chunks(ty.len())
                    .map(|nodes| ty.to_bin_repr(nodes).unwrap())
                    .collect(),
            ),
        };

        Ok(encoded)
    }
}

impl Display for ValueType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ValueType::Bit => write!(f, "Bit"),
            ValueType::U8 => write!(f, "U8"),
            ValueType::U16 => write!(f, "U16"),
            ValueType::U32 => write!(f, "U32"),
            ValueType::U64 => write!(f, "U64"),
            ValueType::U128 => write!(f, "U128"),
            ValueType::Array(ty, len) => write!(f, "Array<{}, {}>", ty, len),
        }
    }
}

macro_rules! impl_value_type {
    ($ty:ty, $ident:ident) => {
        impl StaticValueType for $ty {
            fn value_type() -> ValueType {
                ValueType::$ident
            }
        }

        impl<const N: usize> StaticValueType for [$ty; N] {
            fn value_type() -> ValueType {
                ValueType::Array(Box::new(ValueType::$ident), N)
            }
        }
    };
}

impl_value_type!(bool, Bit);
impl_value_type!(u8, U8);
impl_value_type!(u16, U16);
impl_value_type!(u32, U32);
impl_value_type!(u64, U64);
impl_value_type!(u128, U128);

/// A value that can be encoded into a binary representation.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum Value {
    Bit(bool),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
    Array(Vec<Value>),
}

impl Value {
    /// Returns the type of the value.
    pub fn value_type(&self) -> ValueType {
        match self {
            Value::Bit(_) => ValueType::Bit,
            Value::U8(_) => ValueType::U8,
            Value::U16(_) => ValueType::U16,
            Value::U32(_) => ValueType::U32,
            Value::U64(_) => ValueType::U64,
            Value::U128(_) => ValueType::U128,
            Value::Array(v) => ValueType::Array(Box::new(v[0].value_type()), v.len()),
        }
    }
}

impl ToBitsIter for Value {
    type Lsb0Iter = Box<dyn Iterator<Item = bool> + Send + 'static>;
    type Msb0Iter = Box<dyn Iterator<Item = bool> + Send + 'static>;

    fn into_lsb0_iter(self) -> Self::Lsb0Iter {
        match self {
            Value::Bit(v) => Box::new(std::iter::once(v)),
            Value::U8(v) => Box::new(v.into_lsb0_iter()),
            Value::U16(v) => Box::new(v.into_lsb0_iter()),
            Value::U32(v) => Box::new(v.into_lsb0_iter()),
            Value::U64(v) => Box::new(v.into_lsb0_iter()),
            Value::U128(v) => Box::new(v.into_lsb0_iter()),
            Value::Array(v) => Box::new(v.into_iter().flat_map(|v| v.into_lsb0_iter())),
        }
    }

    fn into_msb0_iter(self) -> Self::Msb0Iter {
        match self {
            Value::Bit(v) => Box::new(std::iter::once(v)),
            Value::U8(v) => Box::new(v.into_msb0_iter()),
            Value::U16(v) => Box::new(v.into_msb0_iter()),
            Value::U32(v) => Box::new(v.into_msb0_iter()),
            Value::U64(v) => Box::new(v.into_msb0_iter()),
            Value::U128(v) => Box::new(v.into_msb0_iter()),
            Value::Array(v) => Box::new(v.into_iter().flat_map(|v| v.into_msb0_iter())),
        }
    }
}

impl ToBits for Value {
    fn into_lsb0(self) -> Vec<bool> {
        match self {
            Value::Bit(v) => vec![v],
            Value::U8(v) => v.into_lsb0(),
            Value::U16(v) => v.into_lsb0(),
            Value::U32(v) => v.into_lsb0(),
            Value::U64(v) => v.into_lsb0(),
            Value::U128(v) => v.into_lsb0(),
            Value::Array(v) => v.into_iter().flat_map(|v| v.into_lsb0()).collect(),
        }
    }

    fn into_lsb0_boxed(self: Box<Self>) -> Vec<bool> {
        self.into_lsb0()
    }

    fn into_msb0(self) -> Vec<bool> {
        match self {
            Value::Bit(v) => vec![v],
            Value::U8(v) => v.into_msb0(),
            Value::U16(v) => v.into_msb0(),
            Value::U32(v) => v.into_msb0(),
            Value::U64(v) => v.into_msb0(),
            Value::U128(v) => v.into_msb0(),
            Value::Array(v) => v.into_iter().flat_map(|v| v.into_msb0()).collect(),
        }
    }

    fn into_msb0_boxed(self: Box<Self>) -> Vec<bool> {
        self.into_msb0()
    }
}

impl Display for Value {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Value::Bit(v) => write!(f, "Bit({})", v),
            Value::U8(v) => write!(f, "U8({})", v),
            Value::U16(v) => write!(f, "U16({})", v),
            Value::U32(v) => write!(f, "U32({})", v),
            Value::U64(v) => write!(f, "U64({})", v),
            Value::U128(v) => write!(f, "U128({})", v),
            Value::Array(v) => write!(f, "Array({:?})", v),
        }
    }
}
