use crate::{matrix::ByteMatrix, ot::kos15refactor::BASE_COUNT, Block};
use aes::{BlockCipher, BlockEncrypt};
use cipher::consts::U16;
use clmul::Clmul;
use rand::{Rng, SeedableRng};
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

/// Performs the KOS15 check explained in the paper
pub fn kos15_check(rng: &mut ChaCha12Rng, matrix: &ByteMatrix, choices: &[bool]) -> [Clmul; 3] {
    // Check correlation
    // The check is explaned in the KOS15 paper in a paragraph on page 8
    // starting with "To carry out the check..."
    // We use the exact same notation as the paper.

    // Seeding with a value from cointoss so that neither party could influence
    // the randomness
    let mut x = Clmul::new(&[0u8; BASE_COUNT / 8]);
    let mut t0 = Clmul::new(&[0u8; BASE_COUNT / 8]);
    let mut t1 = Clmul::new(&[0u8; BASE_COUNT / 8]);
    for (j, xj) in choices.into_iter().enumerate() {
        let mut tj = [0u8; BASE_COUNT / 8];
        tj.copy_from_slice(&matrix[BASE_COUNT / 8 * j..BASE_COUNT / 8 * (j + 1)]);
        let mut tj = Clmul::new(&tj);
        // chi is the random weight
        let chi: [u8; BASE_COUNT / 8] = rng.gen();
        let mut chi = Clmul::new(&chi);
        if *xj {
            x ^= chi;
        }
        // Multiplication in the finite field (p.14 Implementation Optimizations.
        // suggests that it can be done without reduction).
        tj.clmul_reuse(&mut chi);
        t0 ^= tj;
        t1 ^= chi;
    }
    [x, t0, t1]
}

pub fn decrypt_values<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
    cipher: &C,
    ciphertexts: &[[Block; 2]],
    table: &[u8],
    choice: &[bool],
) -> Vec<Block> {
    let mut values: Vec<Block> = Vec::with_capacity(choice.len());
    for (j, b) in choice.iter().enumerate() {
        let t: [u8; BASE_COUNT / 8] = table[BASE_COUNT / 8 * j..BASE_COUNT / 8 * (j + 1)]
            .try_into()
            .unwrap();
        let t = Block::from(t);
        let y = if *b {
            ciphertexts[j][1]
        } else {
            ciphertexts[j][0]
        };
        let y = y ^ t.hash_tweak(cipher, j);
        values.push(y);
    }
    values
}
