use mpz_core::utils::blake3;
use num::{traits::ToBytes, BigInt, BigUint};
use std::slice::Chunks;

/// Statistical security parameter.
pub const SSP: usize = 40;

/// The state of the encoding.
#[derive(PartialEq, Clone)]
pub enum EncodingState {
    /// The original unmodified state.
    Original,
    /// The state where the correlation between this encoding and its complementary encoding
    /// was removed.
    Uncorrelated,
    /// The state after the encoding was made uncorrelated and truncated.
    Converted,
}

/// An encoding of a value of a bit, i.e. it encodes either the 0 or the 1 value.
#[derive(Clone, PartialEq)]
pub struct Encoding {
    value: BigUint,
    state: EncodingState,
}
impl Encoding {
    pub fn new(value: BigUint) -> Self {
        Self {
            value,
            state: EncodingState::Original,
        }
    }

    /// Converts the encoding into a `UncorrelatedAndTruncated` state.
    pub fn convert(&self, bit: bool) -> Self {
        let uncorrelated = self.break_correlation(bit);
        uncorrelated.truncate()
    }

    /// Breaks the correlation which this encoding has with its complementary encoding.
    /// Returns an uncorrelated encoding.
    ///
    /// In half-gates garbling scheme, each pair of bit encodings is correlated by a global delta.
    /// It is essential for the security of the AuthDecode protocol that this correlation is removed.   
    ///
    /// # Panics
    ///
    /// Panics it the encoding is not in the `Original` state.
    fn break_correlation(&self, bit: bool) -> Self {
        assert!(self.state == EncodingState::Original);

        // Hash the encoding if it encodes bit 1, otherwise keep the encoding.
        if bit {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&blake3(&self.value.to_be_bytes())[0..16]);
            Self {
                value: BigUint::from_bytes_be(&bytes),
                state: EncodingState::Uncorrelated,
            }
        } else {
            Self {
                value: self.value.clone(),
                state: EncodingState::Uncorrelated,
            }
        }
    }

    /// Truncates the encoding to SSP most significant bits.
    ///
    /// Truncation is an optimization. Using encodings of bitlength > SSP is also acceptable.
    ///
    /// Note: this implementation assumes that the MSBs are private. This is in line with
    /// most garbled circuits implementations which designate the LSB as a public "pointer" bit.  
    /// # Panics
    ///
    /// Panics it the encoding is not in the `Uncorrelated` state.
    fn truncate(self) -> Self {
        assert!(self.state == EncodingState::Uncorrelated);

        let mut digits = self.value.to_radix_be(2);
        // In an unlikely case when there are too few bits, prepend zero bits.
        if digits.len() < SSP {
            digits = [vec![0u8; SSP - digits.len()], digits].concat();
        }
        Self {
            // Safe to unwrap, since all digits are radix-2.
            value: BigUint::from_radix_be(&digits[0..SSP], 2).unwrap(),
            state: EncodingState::Converted,
        }
    }

    pub fn value(&self) -> BigUint {
        self.value.clone()
    }
}

/// Active encodings.
#[derive(Clone, Default, PartialEq)]
pub struct ActiveEncodings(Vec<Encoding>);

impl ActiveEncodings {
    pub fn new(encodings: Vec<Encoding>) -> Self {
        Self(encodings)
    }

    /// Returns the number of active encodings.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns an iterator over `chunk_size` elements at a time.
    pub fn chunks(&self, chunk_size: usize) -> Chunks<'_, Encoding> {
        self.0.chunks(chunk_size)
    }

    pub fn extend(&mut self, other: ActiveEncodings) {
        self.0.extend(other.0)
    }

    /// Converts the encodings ... TODO
    ///
    /// Panics
    pub fn convert(&self, bits: &[bool]) -> Self {
        assert!(self.0.len() == bits.len());

        let converted = self
            .0
            .iter()
            .zip(bits)
            .map(|(enc, bit)| enc.convert(*bit))
            .collect::<Vec<_>>();

        Self(converted)
    }

    /// Computes the arithmetic sum of the converted encodings.
    ///
    /// Panics if any of the encodings has not yet been converted.
    pub fn compute_encoding_sum(&self) -> BigUint {
        self.0.iter().fold(BigUint::from(0u128), |acc, x| {
            assert!(x.state == EncodingState::Converted);
            acc + x.value()
        })
    }

    /// Returns an iterator ... TODO
    pub fn into_chunks(self, chunk_size: usize) -> ActiveEncodingsChunks {
        ActiveEncodingsChunks {
            chunk_size,
            encodings: self.0,
        }
    }
}

pub struct ActiveEncodingsChunks {
    chunk_size: usize,
    encodings: Vec<Encoding>,
}

impl Iterator for ActiveEncodingsChunks {
    type Item = ActiveEncodings;

    fn next(&mut self) -> Option<Self::Item> {
        let remaining = self.encodings.len();
        if remaining == 0 {
            return None;
        }

        let encodings = if remaining <= self.chunk_size {
            std::mem::take(&mut self.encodings)
        } else {
            // TODO use iter() with take
            let new_after_split = self.encodings.split_off(self.chunk_size);
            let split = self.encodings.clone();
            self.encodings = new_after_split;
            split
        };

        Some(ActiveEncodings(encodings))
    }
}

pub trait ToActiveEncodings {
    fn to_active_encodings(&self) -> ActiveEncodings;
}

/// Full encodings.
///
/// Each pair of encodings encodes the 0 and 1 values of a bit.
#[derive(Clone, Default, PartialEq)]
pub struct FullEncodings(Vec<[Encoding; 2]>);
// TODO we need to add state here as well

impl FullEncodings {
    pub fn new(encodings: Vec<[Encoding; 2]>) -> Self {
        Self(encodings)
    }

    /// Returns the number of pairs of full encodings.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns an iterator over `chunk_size` elements at a time.
    pub fn chunks(&self, chunk_size: usize) -> Chunks<'_, [Encoding; 2]> {
        self.0.chunks(chunk_size)
    }

    pub fn convert(self) -> Self {
        // TODO add state and check that no prev. conversion happened
        let converted = self
            .0
            .iter()
            .map(|pair| [pair[0].convert(false), pair[1].convert(true)])
            .collect::<Vec<_>>();
        Self(converted)
        // TODO modify in-place instead
    }

    /// Returns an iterator ... TODO
    pub fn into_chunks(self, chunk_size: usize) -> FullEncodingsChunks {
        FullEncodingsChunks {
            chunk_size,
            encodings: self.0,
        }
    }

    /// Divides one slice into two at an index... TODO
    ///
    /// # Panics
    ///
    /// Panics if `mid > len`.
    pub fn split_at(&self, mid: usize) -> (Self, Self) {
        let (left, right) = self.0.split_at(mid);
        (Self(left.to_vec()), Self(right.to_vec()))
    }

    /// Encodes the provided bits.
    ///
    /// Panics TODO
    pub fn encode(&self, bits: &[bool]) -> ActiveEncodings {
        assert!(self.len() == bits.len());

        let active = self
            .0
            .iter()
            .zip(bits.iter())
            .map(|(enc_pair, bit)| {
                if *bit {
                    enc_pair[1].clone()
                } else {
                    enc_pair[0].clone()
                }
            })
            .collect::<Vec<_>>();

        ActiveEncodings::new(active)
    }

    /// Computes the arithmetic sum of the 0 bit encodings.
    pub fn compute_zero_sum(&self) -> BigUint {
        self.0
            .iter()
            .fold(BigUint::from(0u8), |acc, x| acc + x[0].value())
    }

    /// Computes the arithmetic difference between a pair of encodings.
    pub fn compute_deltas(&self) -> Vec<BigInt> {
        self.0
            .iter()
            .map(|pair| BigInt::from(pair[1].value()) - BigInt::from(pair[0].value()))
            .collect()
    }
}

pub struct FullEncodingsChunks {
    chunk_size: usize,
    encodings: Vec<[Encoding; 2]>,
}

impl Iterator for FullEncodingsChunks {
    type Item = FullEncodings;

    fn next(&mut self) -> Option<Self::Item> {
        let remaining = self.encodings.len();
        if remaining == 0 {
            return None;
        }

        let encodings = if remaining <= self.chunk_size {
            std::mem::take(&mut self.encodings)
        } else {
            let new_after_split = self.encodings.split_off(self.chunk_size);
            let split = self.encodings.clone();
            self.encodings = new_after_split;
            split
        };

        Some(FullEncodings(encodings))
    }
}

pub trait ToFullEncodings {
    fn to_full_encodings(&self) -> FullEncodings;
}
