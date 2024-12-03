//! Specs for Poseidon permutations based on:
//! [ref1] - https://github.com/iden3/circomlib/blob/0a045aec50d51396fcd86a568981a5a0afb99e95/circuits/poseidon.circom

use ff::Field;
use halo2_poseidon::poseidon::primitives::{Mds, Spec};
use halo2_proofs::halo2curves::bn256::Fr as F;

use crate::generated;

/// The number of partial rounds for each supported rate.
///
/// The first element in the array corresponds to rate 1.
/// (`N_ROUNDS_P` in ref1).
const N_ROUNDS_P: [usize; 16] = [
    56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68,
];

/// The number of full rounds.
///
/// (`nRoundsF` in ref1).
const FULL_ROUNDS: usize = 8;

#[derive(Debug, Clone, Copy)]
pub struct CircomlibSpec<const WIDTH: usize, const RATE: usize>;

impl<const WIDTH: usize, const RATE: usize> Spec<F, WIDTH, RATE> for CircomlibSpec<WIDTH, RATE> {
    fn full_rounds() -> usize {
        FULL_ROUNDS
    }

    fn partial_rounds() -> usize {
        N_ROUNDS_P[RATE - 1]
    }

    fn sbox(val: F) -> F {
        val.pow_vartime([5])
    }

    fn secure_mds() -> usize {
        unimplemented!()
    }

    fn constants() -> (Vec<[F; WIDTH]>, Mds<F, WIDTH>, Mds<F, WIDTH>) {
        generated::provide_constants::<WIDTH>()
    }
}
