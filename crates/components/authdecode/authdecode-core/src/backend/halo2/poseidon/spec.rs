use super::{rate15_params, rate1_params};
use crate::backend::halo2::poseidon::rate2_params;
use group::ff::Field;
use halo2_poseidon::poseidon::primitives::Spec;
use halo2_proofs::halo2curves::bn256::Fr as F;

/// The type used to hold the MDS matrix and its inverse.
pub(crate) type Mds<F, const T: usize> = [[F; T]; T];

/// The spec for rate-15 Poseidon used both inside the circuit and in the clear.
// Patterned after https://github.com/privacy-scaling-explorations/poseidon-gadget/blob/764a682ee448bfbde0cc92a04d241fe738ba2d14/src/poseidon/primitives/p128pow5t3.rs#L15
#[derive(Debug)]
pub struct Spec15;

impl Spec<F, 16, 15> for Spec15 {
    fn full_rounds() -> usize {
        8
    }

    fn partial_rounds() -> usize {
        // Taken from https://github.com/iden3/circomlib/blob/master/circuits/poseidon.circom
        // (see "var N_ROUNDS_P[16]"), where they use 64 partial rounds for 15-rate Poseidon
        64
    }

    fn sbox(val: F) -> F {
        val.pow_vartime([5])
    }

    fn secure_mds() -> usize {
        unimplemented!()
    }

    fn constants() -> (Vec<[F; 16]>, Mds<F, 16>, Mds<F, 16>) {
        (
            rate15_params::ROUND_CONSTANTS[..].to_vec(),
            rate15_params::MDS,
            rate15_params::MDS_INV,
        )
    }
}

/// The spec for rate-2 Poseidon used both inside the circuit and in the clear.
// Patterned after https://github.com/privacy-scaling-explorations/poseidon-gadget/blob/764a682ee448bfbde0cc92a04d241fe738ba2d14/src/poseidon/primitives/p128pow5t3.rs#L15
#[derive(Debug)]
pub struct Spec2;

impl Spec<F, 3, 2> for Spec2 {
    fn full_rounds() -> usize {
        8
    }

    fn partial_rounds() -> usize {
        // Taken from https://github.com/iden3/circomlib/blob/master/circuits/poseidon.circom
        // (see "var N_ROUNDS_P[16]"), where they use 57 partial rounds for 2-rate Poseidon.
        // Note: the Poseidon gadget requires the round count to be an even number acc.to
        // https://github.com/privacy-scaling-explorations/poseidon-gadget/blob/764a682ee448bfbde0cc92a04d241fe738ba2d14/src/poseidon/pow5.rs#L67
        56
    }

    fn sbox(val: F) -> F {
        val.pow_vartime([5])
    }

    fn secure_mds() -> usize {
        unimplemented!()
    }

    fn constants() -> (Vec<[F; 3]>, Mds<F, 3>, Mds<F, 3>) {
        (
            rate2_params::ROUND_CONSTANTS[..].to_vec(),
            rate2_params::MDS,
            rate2_params::MDS_INV,
        )
    }
}

/// The spec for rate-1 Poseidon used both inside the circuit and in the clear.
// Patterned after https://github.com/privacy-scaling-explorations/poseidon-gadget/blob/764a682ee448bfbde0cc92a04d241fe738ba2d14/src/poseidon/primitives/p128pow5t3.rs#L15
#[derive(Debug)]
pub struct Spec1;

impl Spec<F, 2, 1> for Spec1 {
    fn full_rounds() -> usize {
        8
    }

    fn partial_rounds() -> usize {
        // Taken from https://github.com/iden3/circomlib/blob/master/circuits/poseidon.circom
        // (see "var N_ROUNDS_P[16]"), where they use 56 partial rounds for 1-rate Poseidon
        56
    }

    fn sbox(val: F) -> F {
        val.pow_vartime([5])
    }

    fn secure_mds() -> usize {
        unimplemented!()
    }

    fn constants() -> (Vec<[F; 2]>, Mds<F, 2>, Mds<F, 2>) {
        (
            rate1_params::ROUND_CONSTANTS[..].to_vec(),
            rate1_params::MDS,
            rate1_params::MDS_INV,
        )
    }
}
