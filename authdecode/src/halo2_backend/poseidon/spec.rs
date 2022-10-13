use super::{rate15_params, rate1_params};
use group::ff::Field;
use halo2_gadgets::poseidon::primitives::Spec;
use pasta_curves::pallas::Base as F;

/// The type used to hold the MDS matrix and its inverse.
pub(crate) type Mds<F, const T: usize> = [[F; T]; T];

/// Spec for rate 15 Poseidon. halo2 uses this spec both inside
/// the zk circuit and in the clear.
///
/// Compare it to the spec which zcash uses:
/// [halo2_gadgets::poseidon::primitives::P128Pow5T3]
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
        val.pow_vartime(&[5])
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

/// Spec for rate 1 Poseidon which halo2 uses both inside
/// the zk circuit and in the clear.
///
/// Compare it to the spec which zcash uses:
/// [halo2_gadgets::poseidon::primitives::P128Pow5T3]
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
        val.pow_vartime(&[5])
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
