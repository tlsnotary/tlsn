pub(crate) mod circuit_config;
mod rate15_params;
mod rate1_params;
mod rate2_params;
pub(crate) mod spec;

use halo2_poseidon::poseidon::primitives::{ConstantLength, Hash};
use halo2_proofs::halo2curves::bn256::Fr as F;

use spec::{Spec1, Spec15, Spec2};

/// Hashes inputs with rate 15 Poseidon and returns the digest
///
/// Patterned after [halo2_gadgets::poseidon::pow5]
/// (see in that file tests::poseidon_hash())
pub fn poseidon_15(field_elements: &[F; 15]) -> F {
    Hash::<F, Spec15, ConstantLength<15>, 16, 15>::init().hash(*field_elements)
}

/// Hashes inputs with rate 2 Poseidon and returns the digest
///
/// Patterned after [halo2_gadgets::poseidon::pow5]
/// (see in that file tests::poseidon_hash())
pub fn poseidon_2(field_elements: &[F; 2]) -> F {
    Hash::<F, Spec2, ConstantLength<2>, 3, 2>::init().hash(*field_elements)
}

/// Hashes inputs with rate 1 Poseidon and returns the digest
///
/// Patterned after [halo2_gadgets::poseidon::pow5]
/// (see in that file tests::poseidon_hash())
pub fn poseidon_1(field_elements: &[F; 1]) -> F {
    Hash::<F, Spec1, ConstantLength<1>, 2, 1>::init().hash(*field_elements)
}
