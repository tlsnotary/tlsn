//! Poseidon permutation over the bn256 curve compatible with iden3's circomlib.

use halo2_poseidon::poseidon::primitives::{permute, Spec};

pub use crate::spec::CircomlibSpec;
pub use halo2_proofs::halo2curves::bn256::Fr as F;

mod generated;
mod spec;

macro_rules! hash {
    ($input:expr, $len:expr) => {{
        const RATE: usize = $len;
        const WIDTH: usize = RATE + 1;

        let mut state = [F::zero(); WIDTH];
        // The first element of the state is initialized to 0.
        state[1..].copy_from_slice($input);

        let (round_constants, mds, _) = CircomlibSpec::<WIDTH, RATE>::constants();
        permute::<F, CircomlibSpec<WIDTH, RATE>, WIDTH, RATE>(&mut state, &mds, &round_constants);

        state[0]
    }};
}

/// Hashes the provided `input` field elements returning the digest.
///
/// # Panics
///
/// Panics if the provided `input` length is larger than 16.
pub fn hash(input: &[F]) -> F {
    match input.len() {
        1 => hash!(input, 1),
        2 => hash!(input, 2),
        3 => hash!(input, 3),
        4 => hash!(input, 4),
        5 => hash!(input, 5),
        6 => hash!(input, 6),
        7 => hash!(input, 7),
        8 => hash!(input, 8),
        9 => hash!(input, 9),
        10 => hash!(input, 10),
        11 => hash!(input, 11),
        12 => hash!(input, 12),
        13 => hash!(input, 13),
        14 => hash!(input, 14),
        15 => hash!(input, 15),
        16 => hash!(input, 16),
        _ => unimplemented!("input length larger than 16 is not supported"),
    }
}
