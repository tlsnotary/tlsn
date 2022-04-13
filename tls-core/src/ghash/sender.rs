// implements the GHASH sender. This is the party which holds the X value of
// block multiplication. The sender acts as the sender of the Oblivious
// Transfer and sends masked x_table entries obliviously for each
// bit of Y received from the GHASH receiver.

use super::utils::{block_mult, find_max_odd_power, free_square, square_all, strategy1, strategy2};
use rand::{CryptoRng, Rng};
use std::collections::BTreeMap;

// R is GCM polynomial in little-endian. In hex: "E1000000000000000000000000000000"
const R: u128 = 299076299051606071403356588563077529600;

pub struct GhashSender<R> {
    // blocks are input blocks for GHASH. In TLS the first block is AAD,
    // the middle blocks are AES blocks - the ciphertext, the last block
    // is len(AAD)+len(ciphertext)
    blocks: Vec<u128>,
    // powers are our XOR shares of the powers of H (H is the GHASH key).
    // We need as many powers as there blocks. Value at key==1 corresponds to the share
    // of H^1, value at key==2 to the share of H^2 etc.
    // (Note that type BTreeMap was chosen because it automatically sorts the
    // map by keys, which is what we need).
    powers: BTreeMap<u16, u128>,
    rng: R,
    // max_odd_power is the maximum odd power that we'll need to compute
    // GHASH in 2PC using Block Aggregation
    max_odd_power: u8,
}

impl<R: Rng + CryptoRng> GhashSender<R> {
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

    // See comments in GhashReceiver

    // masked_xtable_for_finished returns masked xtable values needed to
    // compute GHASH in 2PC for TLS's Client_Finished and Server_Finished and
    // also returns our GHASH share.
    // Since the receiver (R) sends bits for his powers in ascending order, we need to
    // accomodate that order, i.e. if we need to multiply R's H^1 by
    // our H^2 and then multiply R's H^2 by our H^1, then we return [xtable
    // for H^2 + xtable for H^1].
    pub fn masked_xtable_for_finished(&mut self) -> (Vec<[u128; 2]>, u128) {
        self.powers.insert(2, free_square(self.powers[&1]));
        let (mut masked1, h3_share1) = self.masked_xtable(self.powers[&1]);
        let (mut masked2, h3_share2) = self.masked_xtable(self.powers[&2]);

        self.powers.insert(
            3,
            block_mult(self.powers[&1], self.powers[&2]) ^ h3_share1 ^ h3_share2,
        );
        let ghash_share = block_mult(self.blocks[0], self.powers[&3])
            ^ block_mult(self.blocks[1], self.powers[&2])
            ^ block_mult(self.blocks[2], self.powers[&1]);

        let mut allMasked: Vec<[u128; 2]> = Vec::new();
        allMasked.append(&mut masked2);
        allMasked.append(&mut masked1);
        (allMasked, ghash_share)
    }

    pub fn step1(&mut self) -> Vec<Vec<[u128; 2]>> {
        self.powers = square_all(&self.powers, self.blocks.len() as u16);
        return self.masked_xtables_for_round(1);
    }

    // returns a vector of xtables
    pub fn masked_xtables_for_round(&mut self, roundNo: u8) -> Vec<Vec<[u128; 2]>> {
        assert!(roundNo == 1 || roundNo == 2);
        let strategy;
        if roundNo == 1 {
            strategy = &strategy1;
        } else {
            strategy = &strategy2;
        }
        let mut all_xtables: Vec<Vec<[u128; 2]>> = Vec::new();
        for (key, value) in strategy.iter() {
            if *key > self.max_odd_power {
                break;
            }
            // since receiver sends bits in ascending order: factor1, factor2,
            // we must return xtables in descending order factor2, factor1;
            let factor1 = self.powers[&(value[0] as u16)];
            let factor2 = self.powers[&(value[1] as u16)];
            let (xtable1, sum1) = self.masked_xtable(factor1);
            let (xtable2, sum2) = self.masked_xtable(factor2);
            all_xtables.push(xtable2);
            all_xtables.push(xtable1);

            // sender's share of power <key> is the locally computed term plus sums
            // of masks of each cross-term.
            let local_term = block_mult(factor1, factor2);
            self.powers.insert(*key as u16, local_term ^ sum1 ^ sum2);
        }
        // since we just added a few new shares of powers, we need to square them
        self.powers = square_all(&self.powers, self.blocks.len() as u16);
        all_xtables
    }

    // masked_xtable returns:
    // 1) a masked xTable from which OT response will be constructed and
    // 2) the XOR-sum of all masks which is our share of the block multiplication product
    // For each value of xTable, the masked xTable will contain 2 values:
    // 1) a random mask and
    // 2) the xTable entry masked with the random mask.
    fn masked_xtable(&mut self, x: u128) -> (Vec<[u128; 2]>, u128) {
        let x_table = self.xtable(x);

        // maskSum is the xor sum of all masks
        let mut mask_sum: u128 = 0;

        let mut masked_xtable: Vec<[u128; 2]> = vec![[0u128; 2]; 128];
        for i in 0..128 {
            let mask: u128 = self.rng.gen();
            mask_sum ^= mask;
            masked_xtable[i][0] = mask;
            masked_xtable[i][1] = x_table[i] ^ mask;
        }
        (masked_xtable, mask_sum)
    }

    // return a table of values of x after each of the 128 rounds of blockMult()
    fn xtable(&mut self, mut x: u128) -> Vec<u128> {
        let mut x_table: Vec<u128> = vec![0u128; 128];
        for i in 0..128 {
            x_table[i] = x;
            x = (x >> 1) ^ ((x & 1) * R);
        }
        x_table
    }
}

#[test]
fn test_ghash_sender() {
    use rand::thread_rng;
    let mut rng = thread_rng();
    let x: u128 = rng.gen();
    let y: u128 = rng.gen();
    let expected = block_mult(x, y);
    assert_eq!(expected, product_from_shares(x, y));

    // corrupt one of the last byte of y value
    let mut bad_bytes = y.to_be_bytes();
    bad_bytes[15] = (bad_bytes[15] + 1) / 255;
    let bad = u128::from_be_bytes(bad_bytes);
    assert_ne!(expected, product_from_shares(x, bad));
}

fn product_from_shares(x: u128, y: u128) -> u128 {
    use mpc_core::utils::u8vec_to_boolvec;
    use rand::thread_rng;

    let rng = thread_rng();
    // instantiate with empty values, we only need rng for this test
    let mut sender = GhashSender::new(rng, 0u128, vec![0u128]);
    let (masked_xtable, my_product_share) = sender.masked_xtable(x);

    // the other party who has the y value will receive only 1 value (out of 2)
    // for each entry in maskedXTable via Oblivious Transfer depending on the
    // bits of y. We simulate that here:
    let mut his_product_share = 0u128;
    let bits = u8vec_to_boolvec(&y.to_be_bytes());
    for i in 0..128 {
        // the first element in xTable corresponds to the highest bit of y
        his_product_share ^= masked_xtable[i][bits[i] as usize];
    }
    my_product_share ^ his_product_share
}
