use super::{matrix::KosMatrix, BASE_COUNT};
use aes::{BlockCipher, BlockEncrypt};
use cipher::consts::U16;
use clmul::Clmul;
use matrix_transpose::LANE_COUNT;
use mpc_core::Block;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;
use std::convert::TryInto;
use utils::bits::{FromBits, IterFromBits};

/// Row length of the transposed KOS15 matrix
const ROW_LENGTH_TR: usize = BASE_COUNT / 8;

/// Helper function to seed ChaChaRngs from a nested slice of blocks
pub fn seed_rngs_from_nested<const N: usize>(seeds: &[[Block; N]]) -> Vec<[ChaCha12Rng; N]> {
    seeds
        .iter()
        .map(|seed| {
            seed.iter()
                .map(|block| {
                    let bytes = block.to_be_bytes();
                    let concat_seed = [bytes, bytes]
                        .concat()
                        .try_into()
                        .expect("Could not convert block into [u8; 32]");
                    ChaCha12Rng::from_seed(concat_seed)
                })
                .collect::<Vec<ChaCha12Rng>>()
                .try_into()
                .unwrap()
        })
        .collect()
}

/// Helper function to seed ChaChaRngs from a slice of blocks
pub fn seed_rngs(seeds: &[Block]) -> Vec<ChaCha12Rng> {
    seeds
        .iter()
        .map(|b| {
            let bytes = b.to_be_bytes();
            ChaCha12Rng::from_seed(
                [bytes, bytes]
                    .concat()
                    .try_into()
                    .expect("Could not convert block into  [u8; 32]"),
            )
        })
        .collect()
}

/// Performs the KOS15 check explained in the paper for the receiver
pub fn kos15_check_receiver(
    rng: &mut ChaCha12Rng,
    matrix: &KosMatrix,
    choices: &[bool],
) -> [Clmul; 3] {
    // Check correlation
    // The check is explained in the KOS15 paper in a paragraph on page 8
    // starting with "To carry out the check..."
    // We use the exact same notation as the paper.

    // Seeding with a value from coin toss so that neither party could influence
    // the randomness
    let mut x = Clmul::new(&[0u8; ROW_LENGTH_TR]);
    let mut t0 = Clmul::new(&[0u8; ROW_LENGTH_TR]);
    let mut t1 = Clmul::new(&[0u8; ROW_LENGTH_TR]);
    for (j, xj) in choices.iter().enumerate() {
        let mut tj = [0u8; ROW_LENGTH_TR];
        tj.copy_from_slice(&matrix[ROW_LENGTH_TR * j..ROW_LENGTH_TR * (j + 1)]);
        let mut tj = Clmul::new(&tj);
        // chi is the random weight
        let chi: [u8; ROW_LENGTH_TR] = rng.gen();
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

/// Performs the KOS15 check for the sender
pub fn kos15_check_sender(
    rng: &mut ChaCha12Rng,
    matrix: &KosMatrix,
    ncols: usize,
    x: &[u8; 16],
    t0: &[u8; 16],
    t1: &[u8; 16],
    base_choices: &[bool],
) -> bool {
    // Check correlation
    // The check is explaned in the KOS15 paper in a paragraph on page 8
    // starting with "To carry out the check..."
    // We use the exact same notation as the paper.
    let mut check0 = Clmul::new(&[0u8; ROW_LENGTH_TR]);
    let mut check1 = Clmul::new(&[0u8; ROW_LENGTH_TR]);
    for j in 0..ncols {
        let mut q = [0u8; ROW_LENGTH_TR];
        q.copy_from_slice(&matrix[ROW_LENGTH_TR * j..ROW_LENGTH_TR * (j + 1)]);
        let mut q = Clmul::new(&q);
        // chi is the random weight
        let chi: [u8; ROW_LENGTH_TR] = rng.gen();
        let mut chi = Clmul::new(&chi);

        // multiplication in the finite field (p.14 Implementation Optimizations.
        // suggests that it can be done without reduction).
        q.clmul_reuse(&mut chi);
        check0 ^= q;
        check1 ^= chi;
    }

    let mut delta = [0u8; ROW_LENGTH_TR];
    let choice_bytes: Vec<u8> = Vec::from_msb0(base_choices.into_iter().copied());
    delta.copy_from_slice(&choice_bytes);
    let delta = Clmul::new(&delta);

    let x = Clmul::new(x);
    let t0 = Clmul::new(t0);
    let t1 = Clmul::new(t1);

    let (tmp0, tmp1) = x.clmul(delta);
    check0 ^= tmp0;
    check1 ^= tmp1;
    if !(check0 == t0 && check1 == t1) {
        return false;
    }
    true
}

/// Encrypt the sender's values
///
/// Having 2 messages that Receiver chooses from, we encrypt each message with
/// a unique mask (i.e. XOR the message them with the mask). Receiver who knows
/// only 1 mask will be able to decrypt only 1 message out of 2.
///
/// The lengths of `inputs`, `table`, and `flip` MUST all be equal. If not, this function panics.
pub fn encrypt_values<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
    cipher: &C,
    inputs: &[[Block; 2]],
    table: &[u8],
    choices: &[bool],
    flip: Option<Vec<bool>>,
) -> Vec<[Block; 2]> {
    // Check that all the lengths match
    assert_eq!(inputs.len() * ROW_LENGTH_TR, table.len());
    if let Some(f) = &flip {
        assert_eq!(table.len(), f.len() * ROW_LENGTH_TR);
    }

    let mut ciphertexts: Vec<[Block; 2]> = Vec::with_capacity(table.len());
    let base_choice: [u8; 16] = choices
        .into_iter()
        .copied()
        .iter_from_msb0()
        .collect::<Vec<u8>>()
        .try_into()
        .expect("choices should be 16 bytes long");
    let delta = Block::from(base_choice);
    // If Receiver used *random* choice bits during OT extension setup, he will now
    // instruct us to de-randomize, so that the value corresponding to his *actual*
    // choice bit would be masked by that mask which Receiver knows.
    let flip = flip.unwrap_or_else(|| vec![false; inputs.len()]);
    for (j, (input, flip)) in inputs.iter().zip(flip).enumerate() {
        let q: [u8; ROW_LENGTH_TR] = table[ROW_LENGTH_TR * j..ROW_LENGTH_TR * (j + 1)]
            .try_into()
            .unwrap();
        let q = Block::from(q);
        let masks = [q.hash_tweak(cipher, j), (q ^ delta).hash_tweak(cipher, j)];
        if flip {
            ciphertexts.push([input[0] ^ masks[1], input[1] ^ masks[0]]);
        } else {
            ciphertexts.push([input[0] ^ masks[0], input[1] ^ masks[1]]);
        }
    }
    ciphertexts
}

/// Decrypt the sender values depending on the receiver choices
pub fn decrypt_values<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
    cipher: &C,
    ciphertexts: &[[Block; 2]],
    table: &[u8],
    choices: &[bool],
) -> Vec<Block> {
    let mut values: Vec<Block> = Vec::with_capacity(choices.len());
    for (j, b) in choices.iter().enumerate() {
        let t: [u8; ROW_LENGTH_TR] = table[ROW_LENGTH_TR * j..ROW_LENGTH_TR * (j + 1)]
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

/// This function calculates the necessary padding for the boolean choices of the receiver, so that
/// the resulting byte matrix will be easy to transpose. It also adds 256 extra choices for the
/// KOS15 check.
pub fn calc_padding(n: usize) -> usize {
    let remainder = n % (LANE_COUNT * 8);
    if remainder == 0 {
        256
    } else {
        256 + LANE_COUNT * 8 - remainder
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kos15_utils_seed_rngs_nested() {
        let blocks = vec![
            [Block::from(0), Block::from(1)],
            [Block::from(2), Block::from(3)],
            [Block::from(4), Block::from(5)],
        ];
        let rngs = seed_rngs_from_nested(&blocks);
        for (k, [rng1, rng2]) in rngs.iter().enumerate() {
            let seed1 = (2 * k as u128).to_be_bytes();
            let seed2 = (2 * k as u128 + 1).to_be_bytes();
            let expected1: [u8; 32] = [seed1, seed1].concat().try_into().unwrap();
            let expected2: [u8; 32] = [seed2, seed2].concat().try_into().unwrap();
            assert_eq!(rng1.get_seed(), expected1);
            assert_eq!(rng2.get_seed(), expected2);
        }
    }

    #[test]
    fn test_kos15_utils_seed_rngs() {
        let blocks = vec![Block::from(0), Block::from(1), Block::from(2)];
        let rngs = seed_rngs(&blocks);
        for (k, rng) in rngs.iter().enumerate() {
            let seed = (k as u128).to_be_bytes();
            let expected: [u8; 32] = [seed, seed].concat().try_into().unwrap();
            assert_eq!(rng.get_seed(), expected);
        }
    }

    // TODO: Add some tests to check this module for correctness
    //    #[test]
    //    fn test_kos15_utils_check_receiver() {
    //        let choices = [true];
    //        let mut rng = ChaCha12Rng::from_seed([0; 32]);
    //        let inner = vec![0_u8; 16];
    //        let matrix = KosMatrix::new(inner, 16).unwrap();
    //
    //        // We now perform the kos15_receiver check
    //        // Invoking the rng with the provided seed, to generate a [u8; 32] will output this:
    //        // [155, 7, 129, 95, 4, 73, 126, 46, 5, 210, 44, 172, 58, 160, 97, 65, 11, 32, 134, 140,
    //        // 198, 25, 21, 76, 66, 161, 198, 27, 233, 144, 39, 23]
    //        kos15_check_receiver(&mut rng, &matrix, &choices);
    //    }
}
