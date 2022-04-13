// implements the GHASH receiver. This is the party which holds the Y value of
// block multiplication. The receiver acts as the receiver of the Oblivious
// Transfer and receives sender's masked x_table entries obliviously for each
// bit of Y.
use super::utils::{block_mult, find_max_odd_power, free_square, square_all, strategy1, strategy2};
use mpc_core::utils::u8vec_to_boolvec;
use rand::{CryptoRng, Rng};
use std::{collections::BTreeMap, convert::TryInto};

pub struct GhashReceiver<R> {
    // blocks are input blocks for GHASH. In TLS the first block is AAD,
    // the middle blocks are AES blocks - the ciphertext, the last block
    // is len(AAD)+len(ciphertext)
    blocks: Vec<u128>,
    // powers are our XOR shares of the powers of H (H is the GHASH key).
    // We need as many powers as there blocks. Value at key==1 corresponds to the share
    // of H^1, value at key==2 to the share of H^2 etc.
    powers: BTreeMap<u16, u128>,
    rng: R,
    // max_odd_power is the maximum odd power that we'll need to compute
    // GHASH in 2PC using Block Aggregation
    max_odd_power: u8,
}

impl<R: Rng + CryptoRng> GhashReceiver<R> {
    pub fn new(rng: R, ghash_key_share: u128, blocks: Vec<u128>) -> Self {
        let mut p = BTreeMap::new();
        p.insert(1, ghash_key_share);
        Self {
            max_odd_power: find_max_odd_power(blocks.len() as u16),
            rng,
            blocks,
            powers: p,
        }
    }

    // The convention for the returned bits:
    // A) powers are in an ascending order: first powers[1], then powers[2] etc.
    // B) bits of each power are placed in least-significant-bit-first
    // order, thus we reverse bits.

    // To demonstrate, let's say that S has his shares H1_s and H2_s and receiver
    // has her shares H1_r and H2_r. They need to compute shares of H3.
    // H3 = (H1_s + H1_r)*(H2_s + H2_r) = H1_s*H2_s + H1_s*H2_r + H1_r*H2_s +
    // H1_r*H2_r. Term 1 can be computed by S locally and term 4 can be
    // computed by R locally. Only terms 2 and 3 will be computed using
    // GHASH 2PC. R will obliviously request values for bits of H1_r and H2_r.
    // The XOR sum of all values which S will send back plus H1_r*H2_r will
    // become R's share of H3.

    // bits_for_finished returns bits of Y needed to build either the TLS's
    // Client_Finished or Server_Finished. Note that one instance of
    // GhashReceiver must be used for CF (and subsequent HTTP request) and a
    // separate instance must be used for SF.
    pub fn bits_for_finished(&mut self) -> Vec<bool> {
        self.powers.insert(2, free_square(self.powers[&1]));
        let mut bits1 = u8vec_to_boolvec(&self.powers[&1].to_be_bytes());
        let mut bits2 = u8vec_to_boolvec(&self.powers[&2].to_be_bytes());
        let mut all_bits: Vec<bool> = Vec::new();
        all_bits.append(&mut bits1);
        all_bits.append(&mut bits2);
        all_bits
    }

    // process_xtable_for_finished takes the masked xtable and computes our
    // share of powers[3]. Then it multiplies each block with the corresponding
    // power and outputs our share of GHASH for the CF or SF message.
    pub fn process_xtable_for_finished(&mut self, xtable: Vec<u128>) -> u128 {
        // the XOR sum of all masked xtable values plus H^1*H^2 is our share of H^3
        self.powers.insert(
            3,
            xtable.iter().fold(0u128, |acc, x| acc ^ x)
                ^ block_mult(self.powers[&1], self.powers[&2]),
        );
        let ghash_share = block_mult(self.blocks[0], self.powers[&3])
            ^ block_mult(self.blocks[1], self.powers[&2])
            ^ block_mult(self.blocks[2], self.powers[&1]);
        ghash_share
    }

    // bits_for_round prepares receiver's choice bits for a
    // given round of communication
    pub fn bits_for_round(&mut self, roundNo: u8) -> Vec<Vec<bool>> {
        assert!(roundNo == 1 || roundNo == 2);
        self.powers = square_all(&self.powers, self.blocks.len() as u16);
        let strategy;
        if roundNo == 1 {
            strategy = &strategy1;
        } else {
            strategy = &strategy2;
        }
        let mut all_bits: Vec<Vec<bool>> = Vec::new();
        for (key, value) in strategy.iter() {
            if *key > self.max_odd_power {
                break;
            }
            all_bits.push(u8vec_to_boolvec(
                &self.powers[&(value[0] as u16)].to_be_bytes(),
            ));
            all_bits.push(u8vec_to_boolvec(
                &self.powers[&(value[1] as u16)].to_be_bytes(),
            ));
        }
        all_bits
    }

    // modifies powers
    pub fn process_xtables_for_round(&mut self, xtables: Vec<Vec<u128>>, roundNo: u8) {
        let strategy;
        if roundNo == 1 {
            strategy = &strategy1;
        } else {
            strategy = &strategy2;
        }
        // for every key in the strategy there must be 2 masked xtables
        assert!(strategy.keys().len() * 2 == xtables.len());
        for (count, (power, factors)) in strategy.iter().enumerate() {
            if *power > self.max_odd_power {
                break;
            }
            // the XOR sum of two masked xtables' values plus the locally computed
            // term is our share of power
            let xor_sum = xtables[count * 2].iter().fold(0u128, |acc, x| acc ^ x)
                ^ xtables[(count * 2) + 1]
                    .iter()
                    .fold(0u128, |acc, x| acc ^ x);
            let local_term = block_mult(
                self.powers[&(factors[0] as u16)],
                self.powers[&(factors[1] as u16)],
            );
            self.powers.insert(*power as u16, xor_sum ^ local_term);
        }
        // since we just added a few new shares of powers, we need to square them
        self.powers = square_all(&self.powers, self.blocks.len() as u16);
    }
}
