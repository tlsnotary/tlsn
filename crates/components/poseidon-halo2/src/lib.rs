//! An experimental Poseidon hash implementation over the BN256 curve with custom parameters.
//!
//! This crate is only meant to be used for experimental purposes. The parameters were not checked
//! to be secure.

mod rate15_params;
mod rate1_params;
mod rate2_params;
mod spec;

use halo2_poseidon::poseidon::primitives::{ConstantLength, Hash};
use halo2_proofs::halo2curves::bn256;

pub use halo2_proofs::halo2curves::bn256::Fr as F;
pub use spec::{Spec1, Spec15, Spec2};

/// Hashes the provided input field elements and returns the digest.
///
/// # Panics
///
/// Panics if the provided input's length is not 15, 2, or 1 field elements.
pub fn hash(input: &[bn256::Fr]) -> bn256::Fr {
    match input.len() {
        15 => Hash::<bn256::Fr, spec::Spec15, ConstantLength<15>, 16, 15>::init()
            .hash(input.try_into().unwrap()),
        2 => Hash::<bn256::Fr, spec::Spec2, ConstantLength<2>, 3, 2>::init()
            .hash(input.try_into().unwrap()),
        1 => Hash::<bn256::Fr, spec::Spec1, ConstantLength<1>, 2, 1>::init()
            .hash(input.try_into().unwrap()),
        _ => unimplemented!(),
    }
}
