use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use utils::bits::{FromBits, ToBitsIter};

use mpc_circuits::types::{StaticValueType, TypeError, Value, ValueType};
use mpc_core::{hash::DomainSeparatedHash, impl_domain_separated_hash, Block};

use crate::encoding::{state, Delta, Label, LabelState, Labels};

/// Error related to encoded values.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum ValueError {
    #[error(transparent)]
    TypeError(#[from] mpc_circuits::types::TypeError),
    #[error("invalid encoding length, expected: {expected}, actual: {actual}")]
    InvalidLength { expected: usize, actual: usize },
    #[error("invalid active encoding")]
    InvalidActiveEncoding,
    #[error("invalid commitment")]
    InvalidCommitment,
}

/// A trait for encoding values.
pub trait Encode: ToBitsIter {
    /// The encoded value type.
    type Encoded;

    /// Encodes a value using the provided delta and labels.
    fn encode(delta: Delta, labels: &[Label]) -> Result<Self::Encoded, ValueError>;
}

macro_rules! define_encoded_value {
    ($($EncodedTy:ident),+) => {
        /// An encoded value.
        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
        #[allow(missing_docs)]
        pub enum EncodedValue<S: LabelState> {
            $(
                $EncodedTy($EncodedTy<S>),
            )*
            Array(Vec<EncodedValue<S>>),
        }

        impl<S: LabelState> EncodedValue<S> {
            /// Returns the value type of the encoded value.
            pub fn value_type(&self) -> ValueType {
                match self {
                    $(
                        EncodedValue::$EncodedTy(_) => ValueType::$EncodedTy,
                    )*
                    EncodedValue::Array(v) => ValueType::Array(Box::new(v[0].value_type()), v.len()),
                }
            }

            /// Returns an iterator over the labels of the encoded value.
            ///
            /// # Note
            ///
            /// When the labels are in the `Full` state, the iterator will return the low labels.
            ///
            /// When the labels are in the `Active` state, the iterator will return the active labels.
            pub fn iter(&self) -> Box<dyn Iterator<Item = &Label> + '_> {
                match self {
                    $(
                        EncodedValue::$EncodedTy(v) => Box::new(v.0.iter()),
                    )*
                    EncodedValue::Array(v) => Box::new(v.iter().flat_map(|v| v.iter())),
                }
            }
        }

        impl EncodedValue<state::Full> {
            /// Returns the delta of the encoded value.
            pub fn delta(&self) -> Delta {
                match self {
                    $(
                        EncodedValue::$EncodedTy(v) => v.0.delta(),
                    )*
                    EncodedValue::Array(v) => v[0].delta(),
                }
            }

            /// Returns the decoding for the encoded value.
            pub fn decoding(&self) -> Decoding {
                Decoding::new(self)
            }

            /// Returns a commitment to the encoding of the value.
            pub fn commit(&self) -> EncodingCommitment {
                EncodingCommitment::new(self)
            }

            /// Creates an encoded value from a value type and a list of labels.
            pub fn from_labels(
                value_type: ValueType,
                delta: Delta,
                labels: &[Label],
            ) -> Result<Self, ValueError> {
                if labels.len() != value_type.len() {
                    return Err(ValueError::InvalidLength {
                        expected: value_type.len(),
                        actual: labels.len(),
                    });
                }

                let encoded = match value_type {
                    $(
                        ValueType::$EncodedTy => {
                            EncodedValue::$EncodedTy(
                                $EncodedTy::<state::Full>::new(delta, labels.try_into().expect("length should match"))
                            )
                        }
                    )*
                    ValueType::Array(ty, _) => EncodedValue::Array(
                        labels
                            .chunks(ty.len())
                            .map(|labels| Self::from_labels((*ty).clone(), delta, labels).expect("length should match"))
                            .collect(),
                    ),
                    _ => unimplemented!("unimplemented value type: {:?}", value_type),
                };

                Ok(encoded)
            }

            /// Returns the active encoding of the provided value.
            pub fn select(
                &self,
                value: impl Into<Value>,
            ) -> Result<EncodedValue<state::Active>, ValueError> {
                let value = value.into();

                let active = match (self, &value) {
                    $(
                        (EncodedValue::$EncodedTy(encoded), Value::$EncodedTy(v)) => {
                            EncodedValue::$EncodedTy(encoded.select(*v))
                        }
                    )*
                    (EncodedValue::Array(encoded), Value::Array(v)) => {
                        if encoded.len() != v.len() {
                            return Err(ValueError::InvalidLength {
                                expected: encoded.len(),
                                actual: v.len(),
                            });
                        }

                        EncodedValue::Array(
                            encoded
                                .iter()
                                .zip(v.iter())
                                .map(|(encoded, v)| encoded.select(v.clone()))
                                .collect::<Result<Vec<_>, _>>()?,
                        )
                    }
                    _ => {
                        return Err(TypeError::UnexpectedType {
                            expected: self.value_type(),
                            actual: value.value_type(),
                        })?;
                    }
                };

                Ok(active)
            }

            /// Verifies that the active encoding is authentic.
            pub fn verify(&self, active: &EncodedValue<state::Active>) -> Result<(), ValueError> {
                match (self, active) {
                    $(
                        (EncodedValue::$EncodedTy(full), EncodedValue::$EncodedTy(active)) => {
                            full.verify(active)
                        }
                    )*
                    (EncodedValue::Array(full), EncodedValue::Array(active))
                        if full.len() == active.len() =>
                    {
                        full.iter()
                            .zip(active.iter())
                            .map(|(full, active)| full.verify(active))
                            .collect::<Result<(), _>>()
                    }
                    _ => Err(TypeError::UnexpectedType {
                        expected: self.value_type(),
                        actual: active.value_type(),
                    })?,
                }
            }

            /// Verifies that the active encoding is authentic and decodes the value.
            pub fn decode(&self, active: &EncodedValue<state::Active>) -> Result<Value, ValueError> {
                self.verify(active)?;
                active.decode(&self.decoding())
            }

            /// Returns an iterator over the blocks of an encoded value.
            pub fn iter_blocks(&self) -> Box<dyn Iterator<Item = [Block; 2]> + Send + '_> {
                match self {
                    $(
                        EncodedValue::$EncodedTy(v) => Box::new(v.0.iter_blocks()),
                    )*
                    EncodedValue::Array(v) => Box::new(v.iter().flat_map(|v| v.iter_blocks())),
                }
            }
        }

        impl EncodedValue<state::Active> {
            /// Creates an encoded value from a value type and a list of labels.
            pub fn from_labels(value_type: ValueType, labels: &[Label]) -> Result<Self, ValueError> {
                if labels.len() != value_type.len() {
                    return Err(ValueError::InvalidLength {
                        expected: value_type.len(),
                        actual: labels.len(),
                    });
                }

                let encoded = match value_type {
                    $(
                        ValueType::$EncodedTy => {
                            EncodedValue::$EncodedTy(
                                $EncodedTy::<state::Active>::new(labels.try_into().unwrap())
                            )
                        }
                    )*
                    ValueType::Array(ty, _) => EncodedValue::Array(
                        labels
                            .chunks(ty.len())
                            .map(|labels| Self::from_labels((*ty).clone(), labels).unwrap())
                            .collect(),
                    ),
                    _ => unimplemented!("unimplemented value type: {:?}", value_type),
                };

                Ok(encoded)
            }

            /// Decodes an encoded value into a value using decoding information.
            pub fn decode(&self, decoding: &Decoding) -> Result<Value, ValueError> {
                let value = match (self, decoding) {
                    $(
                        (EncodedValue::$EncodedTy(v), Decoding::$EncodedTy(d)) => {
                            Value::$EncodedTy(v.decode(&d))
                        }
                    )*
                    (EncodedValue::Array(v), Decoding::Array(d)) => Value::Array(
                        v.iter()
                            .zip(d)
                            .map(|(v, d)| v.decode(&d))
                            .collect::<Result<Vec<_>, _>>()?,
                    ),
                    (v, d) => {
                        return Err(TypeError::UnexpectedType {
                            expected: v.value_type(),
                            actual: d.value_type(),
                        })?
                    }
                };

                Ok(value)
            }

            /// Recovers the full encoding of a value using the decoding and delta.
            pub fn recover(&self, decoding: &Decoding, delta: Delta) -> Result<EncodedValue<state::Full>, TypeError> {
                match (self, decoding) {
                    $(
                        (EncodedValue::$EncodedTy(v), Decoding::$EncodedTy(d)) => {
                            Ok(EncodedValue::$EncodedTy(v.recover(&d, delta)))
                        }
                    )*
                    (EncodedValue::Array(v), Decoding::Array(d)) => {
                        Ok(EncodedValue::Array(v.iter().zip(d).map(|(v, d)| v.recover(&d, delta)).collect::<Result<Vec<_>, _>>()?))
                    }
                    (v, d) => {
                        return Err(TypeError::UnexpectedType {
                            expected: v.value_type(),
                            actual: d.value_type(),
                        })?
                    }
                }
            }

            /// Recovers the full encoding of a value using the known plaintext value and delta.
            pub fn recover_from_value(&self, value: &Value, delta: Delta) -> Result<EncodedValue<state::Full>, TypeError> {
                match (self, value) {
                    $(
                        (EncodedValue::$EncodedTy(encoded), Value::$EncodedTy(v)) => {
                            Ok(EncodedValue::$EncodedTy(encoded.recover_from_value(*v, delta)))
                        }
                    )*
                    (EncodedValue::Array(encoded), Value::Array(values)) => Ok(EncodedValue::Array(
                        encoded.iter()
                            .zip(values)
                            .map(|(encoded, value)| encoded.recover_from_value(value, delta))
                            .collect::<Result<Vec<_>, _>>()?,
                    )),
                    (v, d) => {
                        return Err(TypeError::UnexpectedType {
                            expected: v.value_type(),
                            actual: d.value_type(),
                        })?
                    }
                }
            }
        }
    };
}

define_encoded_value!(Bit, U8, U16, U32, U64, U128);

macro_rules! define_encoded_variant {
    ($EncodedTy:ident, $PlaintextTy:ty, $len:expr) => {
        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
        pub struct $EncodedTy<S: LabelState>(Labels<$len, S>);

        impl $EncodedTy<state::Full> {
            pub(crate) fn new(delta: Delta, labels: [Label; $len]) -> Self {
                Self(Labels::<$len, state::Full>::new(delta, labels))
            }

            /// Returns the active encoding of the plaintext value
            pub(crate) fn select(&self, value: $PlaintextTy) -> $EncodedTy<state::Active> {
                let mut bits = value.into_lsb0_iter();
                let delta = self.0.delta();
                $EncodedTy::<state::Active>::new(self.0.labels.map(|label| {
                    if bits.next().expect("bit length should match") {
                        label ^ delta
                    } else {
                        label
                    }
                }))
            }

            /// Verifies that the active encoding is authentic.
            pub(crate) fn verify(
                &self,
                active: &$EncodedTy<state::Active>,
            ) -> Result<(), ValueError> {
                self.0.verify(&active.0)
            }
        }

        impl $EncodedTy<state::Active> {
            pub(crate) fn new(labels: [Label; $len]) -> Self {
                Self(Labels::<$len, state::Active>::new(labels))
            }
        }

        impl Encode for $PlaintextTy {
            type Encoded = $EncodedTy<state::Full>;

            fn encode(delta: Delta, labels: &[Label]) -> Result<Self::Encoded, ValueError> {
                if labels.len() != $len {
                    return Err(ValueError::InvalidLength {
                        expected: $len,
                        actual: labels.len(),
                    });
                }

                let labels = labels.try_into().expect("bit length should match");

                Ok(Self::Encoded::new(delta, labels))
            }
        }

        impl<const N: usize> Encode for [$PlaintextTy; N] {
            type Encoded = EncodedValue<state::Full>;

            fn encode(delta: Delta, labels: &[Label]) -> Result<Self::Encoded, ValueError> {
                EncodedValue::<state::Full>::from_labels(
                    <[$PlaintextTy; N]>::value_type(),
                    delta,
                    labels,
                )
            }
        }

        impl<S: state::LabelState> From<$EncodedTy<S>> for EncodedValue<S> {
            fn from(value: $EncodedTy<S>) -> Self {
                EncodedValue::$EncodedTy(value)
            }
        }

        impl<S: state::LabelState, const N: usize> From<[$EncodedTy<S>; N]> for EncodedValue<S> {
            fn from(value: [$EncodedTy<S>; N]) -> Self {
                EncodedValue::Array(value.map(|v| v.into()).to_vec())
            }
        }
    };
}

define_encoded_variant!(Bit, bool, 1);
define_encoded_variant!(U8, u8, 8);
define_encoded_variant!(U16, u16, 16);
define_encoded_variant!(U32, u32, 32);
define_encoded_variant!(U64, u64, 64);
define_encoded_variant!(U128, u128, 128);

macro_rules! define_decoding {
    ($( ($EncodedTy:ident, $DecodingTy:ident) ),*) => {
        /// Decoding information for an encoded value.
        ///
        /// This is used to decode an active encoding of a value to its plaintext value.
        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
        #[allow(missing_docs)]
        pub enum Decoding {
            $(
                $EncodedTy($DecodingTy),
            )*
            Array(Vec<Decoding>),
        }

        impl Decoding {
            pub(crate) fn new(value: &EncodedValue<state::Full>) -> Self {
                match value {
                    $(
                        EncodedValue::$EncodedTy(v) => Decoding::$EncodedTy(v.decoding()),
                    )*
                    EncodedValue::Array(v) => Decoding::Array(v.iter().map(|v| Decoding::new(v)).collect()),
                }
            }

            /// Returns the type of the value that this decodes.
            pub fn value_type(&self) -> ValueType {
                match self {
                    $(
                        Decoding::$EncodedTy(_) => ValueType::$EncodedTy,
                    )*
                    Decoding::Array(v) => ValueType::Array(Box::new(v[0].value_type()), v.len()),
                }
            }
        }
    };
}

define_decoding!(
    (Bit, BitDecoding),
    (U8, U8Decoding),
    (U16, U16Decoding),
    (U32, U32Decoding),
    (U64, U64Decoding),
    (U128, U128Decoding)
);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BitDecoding(bool);

impl Bit<state::Full> {
    pub(crate) fn decoding(&self) -> BitDecoding {
        BitDecoding(self.0[0].pointer_bit())
    }
}

impl Bit<state::Active> {
    pub(crate) fn recover(&self, decoding: &BitDecoding, delta: Delta) -> Bit<state::Full> {
        Bit::<state::Full>::new(
            delta,
            self.0.labels.map(|label| {
                if label.pointer_bit() ^ decoding.0 {
                    label ^ delta
                } else {
                    label
                }
            }),
        )
    }

    pub(crate) fn recover_from_value(&self, value: bool, delta: Delta) -> Bit<state::Full> {
        Bit::<state::Full>::new(
            delta,
            self.0
                .labels
                .map(|label| if value { label ^ delta } else { label }),
        )
    }

    pub(crate) fn decode(&self, decoding: &BitDecoding) -> bool {
        self.0[0].pointer_bit() ^ decoding.0
    }
}

macro_rules! define_decoding_info_variant {
    ($name:ident, $value:ident, $ty:ty) => {
        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
        pub struct $name($ty);

        impl $value<state::Full> {
            pub(crate) fn decoding(&self) -> $name {
                $name(<$ty>::from_lsb0(
                    self.0.iter().map(|label| label.pointer_bit()),
                ))
            }
        }

        impl $value<state::Active> {
            /// Recovers the full encoding of this value using the decoding information and delta.
            pub(crate) fn recover(&self, decoding: &$name, delta: Delta) -> $value<state::Full> {
                let mut decoding = decoding.0.into_lsb0_iter();
                $value::<state::Full>::new(
                    delta,
                    self.0.labels.map(|label| {
                        if label.pointer_bit() ^ decoding.next().unwrap() {
                            label ^ delta
                        } else {
                            label
                        }
                    }),
                )
            }

            /// Recovers the full encoding of this value using the plaintext value and delta.
            pub(crate) fn recover_from_value(
                &self,
                value: $ty,
                delta: Delta,
            ) -> $value<state::Full> {
                let mut value = value.into_lsb0_iter();
                $value::<state::Full>::new(
                    delta,
                    self.0.labels.map(|label| {
                        if value.next().unwrap() {
                            label ^ delta
                        } else {
                            label
                        }
                    }),
                )
            }

            /// Decodes this value using the decoding information.
            pub(crate) fn decode(&self, decoding: &$name) -> $ty {
                <$ty>::from_lsb0(
                    self.0
                        .iter()
                        .zip(decoding.0.into_lsb0_iter())
                        .map(|(label, dec)| label.pointer_bit() ^ dec),
                )
                .into()
            }
        }
    };
}

define_decoding_info_variant!(U8Decoding, U8, u8);
define_decoding_info_variant!(U16Decoding, U16, u16);
define_decoding_info_variant!(U32Decoding, U32, u32);
define_decoding_info_variant!(U64Decoding, U64, u64);
define_decoding_info_variant!(U128Decoding, U128, u128);

#[derive(Serialize)]
struct LabelCommit(Label);

impl_domain_separated_hash!(LabelCommit, "LABEL_COMMITMENT");

macro_rules! define_encoding_commitment {
    ($( ($EncodedTy:ident, $CommitmentTy:ident) ),*) => {
        /// A commitment to the encoding of a value.
        ///
        /// Used by the evaluator to detect certain classes of malicious behavior by
        /// the generator.
        ///
        /// After generating a garbled circuit, the generator will compute commitments
        /// to the encoded outputs of the circuit and send them to the evaluator.
        /// The evaluator will then be able to evaluate the circuit and check the
        /// commitments against the active encoding of the outputs.
        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
        #[allow(missing_docs)]
        pub enum EncodingCommitment {
            $(
                $EncodedTy(Box<$CommitmentTy>),
            )*
            Array(Vec<EncodingCommitment>),
        }

        impl EncodingCommitment {
            pub(crate) fn new(value: &EncodedValue<state::Full>) -> EncodingCommitment {
                match value {
                    $(
                        EncodedValue::$EncodedTy(v) => EncodingCommitment::$EncodedTy(Box::new(v.commit())),
                    )*
                    EncodedValue::Array(v) => EncodingCommitment::Array(v.iter().map(|v| v.commit()).collect()),
                }
            }

            /// Returns the type of the value that this commitment is for.
            pub fn value_type(&self) -> ValueType {
                match self {
                    $(
                        EncodingCommitment::$EncodedTy(_) => ValueType::$EncodedTy,
                    )*
                    EncodingCommitment::Array(v) => ValueType::Array(Box::new(v[0].value_type()), v.len()),
                }
            }

            /// Verifies that the given active encoding matches the commitment.
            pub fn verify(&self, active: &EncodedValue<state::Active>) -> Result<(), ValueError> {
                match (self, active) {
                    $(
                        (EncodingCommitment::$EncodedTy(c), EncodedValue::$EncodedTy(a)) => {
                            c.verify(a)?;
                            Ok(())
                        }
                    )*
                    (EncodingCommitment::Array(c), EncodedValue::Array(a)) if c.len() == a.len() => {
                        for (c, a) in c.iter().zip(a.iter()) {
                            c.verify(a)?;
                        }

                        Ok(())
                    }
                    _ => Err(TypeError::UnexpectedType {
                        expected: self.value_type(),
                        actual: active.value_type(),
                    })?,
                }
            }
        }
    };
}

define_encoding_commitment!(
    (Bit, BitCommitment),
    (U8, U8Commitment),
    (U16, U16Commitment),
    (U32, U32Commitment),
    (U64, U64Commitment),
    (U128, U128Commitment)
);

macro_rules! define_encoding_commitment_variant {
    ($name:ident, $value_ident:ident, $len:expr) => {
        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
        pub struct $name(#[serde(with = "serde_arrays")] [[Block; 2]; $len]);

        impl $value_ident<state::Full> {
            pub(crate) fn commit(&self) -> $name {
                $name::new(self)
            }
        }

        impl $name {
            pub(crate) fn new(value: &$value_ident<state::Full>) -> Self {
                // randomly shuffle the two labels inside each pair in order to prevent
                // the evaluator from decoding their active labels using this commitment
                let mut flip = [false; $len];
                thread_rng().fill::<[bool]>(&mut flip);

                let delta = value.0.delta();

                let commitments = std::array::from_fn(|i| {
                    let low = value.0[i];
                    let high = low ^ delta;

                    let low = Self::compute_commitment(low);
                    let high = Self::compute_commitment(high);

                    if flip[i] {
                        [low, high]
                    } else {
                        [high, low]
                    }
                });

                Self(commitments)
            }

            /// Validates encoding against commitment
            ///
            /// If this function returns an error the generator may be malicious
            pub(crate) fn verify(
                &self,
                value: &$value_ident<state::Active>,
            ) -> Result<(), ValueError> {
                if self.0.iter().zip(value.0.iter()).all(|(pair, label)| {
                    let h = Self::compute_commitment(*label);
                    h == pair[0] || h == pair[1]
                }) {
                    Ok(())
                } else {
                    Err(ValueError::InvalidCommitment)
                }
            }

            // We use a truncated Blake3 hash to commit to the labels
            fn compute_commitment(label: Label) -> Block {
                let commitment: [u8; 16] = LabelCommit(label).domain_separated_hash().as_bytes()
                    [..16]
                    .try_into()
                    .expect("slice is 16 bytes");
                commitment.into()
            }
        }
    };
}

define_encoding_commitment_variant!(BitCommitment, Bit, 1);
define_encoding_commitment_variant!(U8Commitment, U8, 8);
define_encoding_commitment_variant!(U16Commitment, U16, 16);
define_encoding_commitment_variant!(U32Commitment, U32, 32);
define_encoding_commitment_variant!(U64Commitment, U64, 64);
define_encoding_commitment_variant!(U128Commitment, U128, 128);

#[cfg(test)]
mod tests {
    use crate::{ChaChaEncoder, Encoder};
    use mpc_circuits::types::StaticValueType;

    use std::marker::PhantomData;

    use rand::{
        distributions::{Distribution, Standard},
        Rng, SeedableRng,
    };
    use rand_chacha::ChaCha12Rng;
    use rstest::*;

    use super::*;

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
    #[case::bit_array(PhantomData::<[bool; 16]>)]
    #[case::u8_array(PhantomData::<[u8; 16]>)]
    #[case::u16_array(PhantomData::<[u16; 16]>)]
    #[case::u32_array(PhantomData::<[u32; 16]>)]
    #[case::u64_array(PhantomData::<[u64; 16]>)]
    #[case::u128_array(PhantomData::<[u128; 16]>)]
    fn test_encoding<T: StaticValueType + Default>(
        encoder: ChaChaEncoder,
        #[case] _pd: PhantomData<T>,
    ) where
        Standard: Distribution<T>,
        T: Into<Value> + Copy,
    {
        let mut rng = ChaCha12Rng::from_seed([0u8; 32]);

        let value: T = rng.gen();

        let encoded: EncodedValue<_> = encoder.encode_by_type(0, &T::value_type()).into();
        let decoding = encoded.decoding();
        let commit = encoded.commit();
        let active = encoded.select(value).unwrap();
        commit.verify(&active).unwrap();
        let decoded_value = active.decode(&decoding).unwrap();

        assert_eq!(encoded.value_type(), T::value_type());
        assert_eq!(active.value_type(), T::value_type());
        assert_eq!(decoding.value_type(), T::value_type());
        assert_eq!(commit.value_type(), T::value_type());
        assert_eq!(decoded_value.value_type(), T::value_type());
        assert_eq!(decoded_value, value.into());
    }
}
