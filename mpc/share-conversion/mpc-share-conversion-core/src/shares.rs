//! Types for representing shares of field elements.

use crate::fields::Field;

use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};

/// A share of a field element.
#[derive(Clone, Copy, Serialize, Deserialize)]
pub enum Share<T> {
    /// An additive share.
    Add(AddShare<T>),
    /// A multiplicative share.
    Mul(MulShare<T>),
}

impl<T> std::fmt::Debug for Share<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Add(_) => f.debug_tuple("Add").field(&"..").finish(),
            Self::Mul(_) => f.debug_tuple("Mul").field(&"..").finish(),
        }
    }
}

/// The type of a share.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShareType {
    /// An additive share.
    Add,
    /// A multiplicative share.
    Mul,
}

impl ShareType {
    /// Creates a share of this type.
    pub fn new_share<F: Field>(&self, share: F) -> Share<F> {
        match self {
            Self::Add => Share::Add(AddShare::new(share)),
            Self::Mul => Share::Mul(MulShare::new(share)),
        }
    }

    /// Creates a share of this type from a slice of summands.
    pub fn new_from_summands<F: Field>(&self, summands: &[F]) -> Share<F> {
        let share = summands.iter().fold(F::zero(), |acc, x| acc + *x);
        match self {
            Self::Add => Share::Add(AddShare::new(share)),
            Self::Mul => Share::Mul(MulShare::new(share)),
        }
    }

    /// Returns the other share type.
    pub fn other(&self) -> Self {
        match self {
            Self::Add => Self::Mul,
            Self::Mul => Self::Add,
        }
    }
}

impl<T> Share<T>
where
    T: Field,
{
    /// Create a new additive share.
    pub fn new_add(share: T) -> Self {
        Self::Add(AddShare::new(share))
    }

    /// Create a new multiplicative share.
    pub fn new_mul(share: T) -> Self {
        Self::Mul(MulShare::new(share))
    }

    /// Returns the type of the share.
    pub fn ty(&self) -> ShareType {
        match self {
            Self::Add(_) => ShareType::Add,
            Self::Mul(_) => ShareType::Mul,
        }
    }

    /// Returns the binary representation of the share.
    pub fn binary_encoding(&self) -> Vec<bool> {
        match self {
            Self::Add(share) => share.0.into_lsb0(),
            Self::Mul(share) => share.0.into_lsb0(),
        }
    }

    /// Returns the field element of the share.
    pub fn to_inner(self) -> T {
        match self {
            Self::Add(share) => share.0,
            Self::Mul(share) => share.0,
        }
    }

    /// Converts the share representation.
    ///
    /// Returns the converted share and the summands to be transferred via oblivious transfer.
    ///
    /// If the share is additive, it will be converted to multiplicative and vice versa.
    ///
    /// # Arguments
    ///
    /// * `rng` - A cryptographically secure random number generator.
    pub fn convert<R: Rng + CryptoRng>(&self, rng: &mut R) -> (Self, Vec<[T; 2]>) {
        match self {
            Self::Add(share) => {
                let (share, summands) = share.to_multiplicative(rng);
                (Self::Mul(share), summands)
            }
            Self::Mul(share) => {
                let (share, summands) = share.to_additive(rng);
                (Self::Add(share), summands)
            }
        }
    }
}

impl<T> From<AddShare<T>> for Share<T> {
    fn from(value: AddShare<T>) -> Self {
        Self::Add(value)
    }
}

impl<T> From<MulShare<T>> for Share<T> {
    fn from(value: MulShare<T>) -> Self {
        Self::Mul(value)
    }
}

/// An additive share of a field element.
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct AddShare<T>(T);

impl<T> std::fmt::Debug for AddShare<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("AddShare").field(&"..").finish()
    }
}

impl<T> AddShare<T>
where
    T: Field,
{
    /// Create a new additive share.
    pub(crate) fn new(share: T) -> Self {
        Self(share)
    }

    /// Turn into a multiplicative share and get values for OT
    pub(crate) fn to_multiplicative<R: Rng + CryptoRng>(
        self,
        rng: &mut R,
    ) -> (MulShare<T>, Vec<[T; 2]>) {
        // We need to exclude 0 here, because it does not have an inverse
        // which is needed later
        let random: T = loop {
            let r = T::rand(rng);
            if r != T::zero() {
                break r;
            }
        };

        // generate random masks
        let mut masks: Vec<T> = (0..T::BIT_SIZE as usize).map(|_| T::rand(rng)).collect();

        // set the last mask such that the sum of all [T::BIT_SIZE] masks equals 0
        masks[T::BIT_SIZE as usize - 1] = -masks
            .iter()
            .take(T::BIT_SIZE as usize - 1)
            .fold(T::zero(), |acc, i| acc + *i);

        // split up our additive share `x` into random summands
        let mut x_summands: Vec<T> = (0..T::BIT_SIZE as usize).map(|_| T::rand(rng)).collect();

        // set the last summand such that the sum of all [T::BIT_SIZE] summands equals `x`
        x_summands[T::BIT_SIZE as usize - 1] = self.0
            + -x_summands
                .iter()
                .take(T::BIT_SIZE as usize - 1)
                .fold(T::zero(), |acc, i| acc + *i);

        // the inverse of the random share will be the multiplicative share for the sender
        let mul_share = MulShare(random.inverse());

        // Each choice bit of the peer's share `y` represents a summand of `y`, e.g.
        // if `y` is 10110 (in binary), then the choice bits in lsb0 order (0,1,1,0,1) represent the
        // summands (0, 10, 100, 0000, 10000).
        // For each peer's summand (called `y_summand`), we send back `(x_summand + y_summand) * random
        // + mask`. The purpose of the mask is to hide the product.

        let summands: Vec<[T; 2]> = (0..T::BIT_SIZE as usize)
            .map(|k| {
                // when y_summand is zero, we send `x_summand * random + mask`
                let v0 = x_summands[k] * random + masks[k];

                // otherwise we send `(x_summand + y_summand) * random + mask`
                let mut bits = vec![false; T::BIT_SIZE as usize];
                bits[k] = true;
                let y_summand = T::from_lsb0(bits);
                let v1 = (x_summands[k] + y_summand) * random + masks[k];

                [v0, v1]
            })
            .collect();

        // when the peer adds up all the received values, the masks will cancel one another out and
        // the remaining `(x + y) * random` will be the peer's multiplicative share

        (mul_share, summands)
    }
}

impl<F> From<F> for AddShare<F>
where
    F: Field,
{
    fn from(share: F) -> Self {
        Self::new(share)
    }
}

/// A multiplicative share of a field element.
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct MulShare<T>(T);

impl<T> std::fmt::Debug for MulShare<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("MulShare").field(&"..").finish()
    }
}

impl<T> MulShare<T>
where
    T: Field,
{
    /// Create a new multiplicative share.
    pub(crate) fn new(share: T) -> Self {
        Self(share)
    }

    /// Turn into an additive share and get values for OT
    pub(crate) fn to_additive<R: Rng + CryptoRng>(self, rng: &mut R) -> (AddShare<T>, Vec<[T; 2]>) {
        // create random masks
        let masks: Vec<T> = (0..T::BIT_SIZE).map(|_| T::rand(rng)).collect();

        // we multiply this share with 2^k and add a mask
        let summands: Vec<[T; 2]> = masks
            .iter()
            .copied()
            .enumerate()
            .map(|(k, t0)| [t0, t0 + (self.0 * T::two_pow(k as u32))])
            .collect();

        // the additive share for the sender is the sum over t0 with a minus sign
        let add_share = AddShare(-masks.into_iter().fold(T::zero(), |acc, i| acc + i));

        (add_share, summands)
    }
}

impl<T> From<T> for MulShare<T>
where
    T: Field,
{
    fn from(share: T) -> Self {
        Self::new(share)
    }
}
