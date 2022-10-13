pub(crate) mod circuit_config;
mod rate15_params;
mod rate1_params;
pub(crate) mod spec;

use halo2_gadgets::poseidon::primitives::{self as poseidon, ConstantLength};
use pasta_curves::pallas::Base as F;
use spec::{Spec1, Spec15};

/// Hashes inputs with rate 15 Poseidon and returns the digest
///
/// Patterned after [halo2_gadgets::poseidon::pow5]
/// (see in that file tests::poseidon_hash())
pub fn poseidon_15(field_elements: &[F; 15]) -> F {
    poseidon::Hash::<F, Spec15, ConstantLength<15>, 16, 15>::init().hash(*field_elements)
}

/// Hashes inputs with rate 1 Poseidon and returns the digest
///
/// Patterned after [halo2_gadgets::poseidon::pow5]
/// (see in that file tests::poseidon_hash())
pub fn poseidon_1(field_elements: &[F; 1]) -> F {
    poseidon::Hash::<F, Spec1, ConstantLength<1>, 2, 1>::init().hash(*field_elements)
}
