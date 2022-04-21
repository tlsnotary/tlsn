#![allow(dead_code)]

mod common;
mod errors;
mod receiver;
mod receiver_tls;
mod sender;
mod utils;

// module ghash implements a method of computing the AES-GCM's GHASH function
// in a secure two-party computation (2PC) setting using 1-of-2 Oblivious
// Transfer (OT). The parties start with their secret shares of H (GHASH key) end at
// the end each gets their share of the GHASH output.
// The method is decribed here:
// (https://tlsnotary.org/how_it_works#section4).

// To demonstrate, let's say that S has his shares H1_s and H2_s and receiver
// has her shares H1_r and H2_r. They need to compute shares of H3.
// H3 = (H1_s + H1_r)*(H2_s + H2_r) = H1_s*H2_s + H1_s*H2_r + H1_r*H2_s +
// H1_r*H2_r. Term 1 can be computed by S locally and term 4 can be
// computed by R locally. Only terms 2 and 3 will be computed using
// GHASH 2PC. R will obliviously request values for bits of H1_r and H2_r.
// The XOR sum of all values which S will send back plus H1_r*H2_r will
// become R's share of H3.

// When performing block multiplication in 2PC, Receiver holds the Y value and
// Sender holds the X value.
// MXTableFull is masked XTable which Sender has at the beginning of OT.
// MXTableFull must not be known to Receiver.
type MXTableFull = Vec<[u128; 2]>;
// MXTable is masked XTable which Receiver will end up having after OT
type MXTable = Vec<u128>;
// YBits are Receiver's bits of Y in big-endian order. Based on these bits
// Sender will send MXTable via OT.
// The convention for the returned Y bits:
// A) powers are in an ascending order: first powers[1], then powers[2] etc.
// B) bits of each power are placed in BE order.
type YBits = Vec<bool>;

#[cfg(test)]
mod tests {
    use super::utils::block_mult;
    use super::{receiver::GhashReceiver, sender::GhashSender};
    use ghash::{
        universal_hash::{NewUniversalHash, UniversalHash},
        GHash,
    };
    use rand::prelude::ThreadRng;
    use rand::{thread_rng, Rng};
    use std::convert::TryInto;

    #[test]
    // test only the Client/Server_Finished
    fn test_ghash_finished_only() {
        let (h, _h_s, _h_r, mut sender, mut receiver, blocks) = ghash_setup();
        let ghash_result = run_finished(&mut sender, &mut receiver);
        assert_eq!(ghash_result, rust_crypto_ghash(h, &blocks));
    }

    #[test]
    // test Finished + state after round 1 (before block aggregation)
    fn test_ghash_round1_before_block_aggregation() {
        let (h, _h_s, _h_r, mut sender, mut receiver, _blocks) = ghash_setup();
        run_finished(&mut sender, &mut receiver);
        // set blocks of TLS application records and compute their GHASH
        set_blocks(&mut sender, &mut receiver, 30);
        run_round1(&mut sender, &mut receiver);

        let s_powers = sender.get_powers();
        let r_powers = receiver.get_powers();
        let all_s_keys: Vec<u16> = s_powers.keys().cloned().collect();
        let all_r_keys: Vec<u16> = r_powers.keys().cloned().collect();
        let expected_keys = vec![1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28];
        let exp_powers = compute_expected_powers(h, 30);

        assert_eq!(all_s_keys, expected_keys);
        assert_eq!(all_r_keys, expected_keys);
        // compare shares of powers against expected powers
        for key in expected_keys.iter() {
            assert_eq!(
                exp_powers[*key as usize],
                *s_powers.get(key).unwrap() ^ *r_powers.get(key).unwrap()
            );
        }
    }

    #[test]
    // test Finished + round 1 with block aggregation
    fn test_ghash_round1() {
        let (h, _h_s, _h_r, mut sender, mut receiver, _blocks) = ghash_setup();
        run_finished(&mut sender, &mut receiver);
        let request_blocks = set_blocks(&mut sender, &mut receiver, 30);
        run_round1(&mut sender, &mut receiver);
        let choice_bits = receiver.get_request_for_block_aggregation().unwrap();
        let (mxtables_full, sender_ghash_share) =
            sender.get_response_for_block_aggregation().unwrap();
        let mxtables = simulate_ot(&choice_bits, &mxtables_full);
        let receiver_ghash_share = receiver
            .process_response_for_block_aggregation(&mxtables)
            .unwrap();
        let ghash = receiver_ghash_share ^ sender_ghash_share;
        assert_eq!(ghash, rust_crypto_ghash(h, &request_blocks));
    }

    #[test]
    // test Finished + round 1 + round 2 with block aggregation
    fn test_ghash_round2() {
        let (h, _h_s, _h_r, mut sender, mut receiver, _blocks) = ghash_setup();
        run_finished(&mut sender, &mut receiver);
        let request_blocks = set_blocks(&mut sender, &mut receiver, 450);
        run_round1(&mut sender, &mut receiver);
        run_round2(&mut sender, &mut receiver);
        let choice_bits = receiver.get_request_for_block_aggregation().unwrap();
        let (mxtables_full, sender_ghash_share) =
            sender.get_response_for_block_aggregation().unwrap();
        let mxtables = simulate_ot(&choice_bits, &mxtables_full);
        let receiver_ghash_share = receiver
            .process_response_for_block_aggregation(&mxtables)
            .unwrap();
        let ghash = receiver_ghash_share ^ sender_ghash_share;
        assert_eq!(ghash, rust_crypto_ghash(h, &request_blocks));
    }

    fn ghash_setup() -> (
        u128,
        u128,
        u128,
        GhashSender<ThreadRng>,
        GhashReceiver,
        Vec<u128>,
    ) {
        let mut rng = thread_rng();
        // h is ghash key
        let h: u128 = rng.gen();
        // h_s is sender's XOR share of h
        let h_s: u128 = rng.gen();
        // h_r is receiver's XOR share of h
        let h_r: u128 = h ^ h_s;

        let blocks: Vec<u128> = vec![rng.gen(), rng.gen(), rng.gen()];
        let sender = GhashSender::new(rng, h_s, blocks.clone());
        let receiver = GhashReceiver::new(h_r, blocks.clone());
        (h, h_s, h_r, sender, receiver, blocks)
    }

    // set_blocks generates random blocks and sets them
    fn set_blocks(
        sender: &mut GhashSender<ThreadRng>,
        receiver: &mut GhashReceiver,
        block_count: u16,
    ) -> Vec<u128> {
        let blocks: Vec<u128> = vec![thread_rng().gen(); block_count as usize];
        sender.set_blocks(blocks.clone()).unwrap();
        receiver.set_blocks(blocks.clone()).unwrap();
        blocks
    }

    // run_finished computes GHASH for the TLS Finished message
    fn run_finished(sender: &mut GhashSender<ThreadRng>, receiver: &mut GhashReceiver) -> u128 {
        let receiver_bits = receiver.get_request_for_finished().unwrap();
        let (masked_xtable_full, sender_ghash_share) = sender.get_response_for_finished().unwrap();
        let masked_xtable = simulate_ot(&receiver_bits, &masked_xtable_full);
        let receiver_ghash_share = receiver
            .process_response_for_finished(&masked_xtable)
            .unwrap();
        let ghash_result = sender_ghash_share ^ receiver_ghash_share;
        ghash_result
    }

    // compute GHASH using RustCrypto's ghash
    fn rust_crypto_ghash(h: u128, blocks: &Vec<u128>) -> u128 {
        let mut ghash = GHash::new(&h.to_be_bytes().into());
        for block in blocks.iter() {
            ghash.update(&block.to_be_bytes().into());
        }
        let b = ghash.finalize().into_bytes();
        u128::from_be_bytes(b.as_slice().try_into().unwrap())
    }

    // prepare the expected powers of h by recursively multiplying h to
    // itself
    fn compute_expected_powers(h: u128, max: u16) -> Vec<u128> {
        // prepare the expected powers of h by recursively multiplying h to
        // itself
        let mut powers: Vec<u128> = vec![0u128; (max + 1) as usize];
        powers[1] = h;
        let mut prev_power = h;
        for i in 2..((max + 1) as usize) {
            powers[i] = block_mult(prev_power, h);
            prev_power = powers[i];
        }
        powers
    }

    // run_round1 runs round 1 of GHASH computation
    fn run_round1(sender: &mut GhashSender<ThreadRng>, receiver: &mut GhashReceiver) {
        let receiver_bits = receiver.get_request_for_round1().unwrap();
        let xtables_full = sender.get_response_for_round1().unwrap();
        let xtables = simulate_ot(&receiver_bits, &xtables_full);
        receiver.process_response_for_round1(&xtables).unwrap();
    }

    // run_round2 runs round 2 of GHASH computation
    fn run_round2(sender: &mut GhashSender<ThreadRng>, receiver: &mut GhashReceiver) {
        let receiver_bits = receiver.get_request_for_round2().unwrap();
        let xtables_full = sender.get_response_for_round2().unwrap();
        let xtables = simulate_ot(&receiver_bits, &xtables_full);
        receiver.process_response_for_round2(&xtables).unwrap();
    }

    // normally receiver will send his bits via OT to get only 1 out of 2 values
    // for each row of masked xtable. Here we simulate this OT behaviour.
    fn simulate_ot(receiver_bits: &Vec<bool>, mxtables_full: &Vec<[u128; 2]>) -> Vec<u128> {
        assert!(receiver_bits.len() == mxtables_full.len());
        let mut mxtables: Vec<u128> = Vec::new();
        for i in 0..mxtables_full.len() {
            let choice = receiver_bits[i] as usize;
            mxtables.push(mxtables_full[i][choice]);
        }
        mxtables
    }
}
