use crate::Block;
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;
use std::convert::TryInto;

/// Helper function to seed ChaChaRngs
pub fn seed_rngs(seeds: &[[Block; 2]]) -> Vec<[ChaCha12Rng; 2]> {
    seeds
        .iter()
        .map(|k| {
            let k0: [u8; 16] = k[0].to_be_bytes();
            let k1: [u8; 16] = k[1].to_be_bytes();
            let k0: [u8; 32] = [k0, k0]
                .concat()
                .try_into()
                .expect("Could not convert block into [u8; 32]");
            let k1: [u8; 32] = [k1, k1]
                .concat()
                .try_into()
                .expect("Could not convert block into [u8; 32]");
            [ChaCha12Rng::from_seed(k0), ChaCha12Rng::from_seed(k1)]
        })
        .collect()
}
