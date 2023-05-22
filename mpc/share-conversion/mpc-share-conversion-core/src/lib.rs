//! This crate implements secure two-party (2PC) multiplication-to-addition (M2A) and
//! addition-to-multiplication (A2M) algorithms, both with semi-honest security.
//!
//! ### M2A algorithm (implementation of chapter 4.1 in <https://link.springer.com/content/pdf/10.1007/3-540-48405-1_8.pdf>)
//! Let `A` be an element of some finite field with `A = a * b`, where `a` is only known to Alice
//! and `b` is only known to Bob. A is unknown to both parties and it is their goal that each of
//! them ends up with an additive share of A. So both parties start with `a` and `b` and want to
//! end up with `x` and `y`, where `A = a * b = x + y`.
//!
//! ### A2M algorithm (adaptation of chapter 4 in <https://www.cs.umd.edu/~fenghao/paper/modexp.pdf>)
//! This is the other way round.
//! Let `A` be an element of some finite field with `A = x + y`, where `x` is only known to Alice
//! and `y` is only known to Bob. A is unknown to both parties and it is their goal that each of
//! them ends up with a multiplicative share of A. So both parties start with `x` and `y` and want to
//! end up with `a` and `b`, where `A = x + y = a * b`.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![deny(unsafe_code)]

pub mod fields;
pub mod msgs;
mod shares;

pub use fields::Field;
pub use shares::{AddShare, MulShare, Share, ShareType};

#[cfg(test)]
mod tests {
    use crate::fields::{gf2_128::Gf2_128, p256::P256};

    use std::marker::PhantomData;

    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;
    use rstest::*;

    #[rstest]
    #[case::gf2_add(ShareType::Add, PhantomData::<Gf2_128>)]
    #[case::gf2_mul(ShareType::Mul, PhantomData::<Gf2_128>)]
    #[case::p256_add(ShareType::Add, PhantomData::<P256>)]
    #[case::p256_mul(ShareType::Mul, PhantomData::<P256>)]
    fn test_conversion<F: Field>(#[case] ty: ShareType, #[case] _pd: PhantomData<F>) {
        let mut rng = ChaCha12Rng::from_seed([0; 32]);

        let a = ty.new_share(F::rand(&mut rng));
        let b = ty.new_share(F::rand(&mut rng));

        let (x, summands) = a.convert(&mut rng);
        let summands = mock_ot(&summands, b);

        let y = ty.new_from_summands(&summands);

        let (a, b, x, y) = (a.to_inner(), b.to_inner(), x.to_inner(), y.to_inner());

        match ty {
            ShareType::Add => assert_eq!(a + b, x * y),
            ShareType::Mul => assert_eq!(a * b, x + y),
        }
    }

    fn mock_ot<F: Field>(summands: &[[F; 2]], receiver_share: Share<F>) -> Vec<F> {
        receiver_share
            .binary_encoding()
            .into_iter()
            .zip(summands)
            .map(
                |(choice, summand)| {
                    if choice {
                        summand[1]
                    } else {
                        summand[0]
                    }
                },
            )
            .collect()
    }
}
