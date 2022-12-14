//! ghash implements a protocol of computing the AES-GCM's GHASH function in a
//! secure two-party computation (2PC) setting using 1-out-of-2 Oblivious
//! Transfer (OT). The parties start with their secret XOR shares of H (the
//! GHASH key) and at the end each gets their XOR share of the GHASH output.
//! The method is decribed here:
//! (https://tlsnotary.org/how_it_works#section4).

//! As an illustration, let's say that S has his shares H1_s and H2_s and R
//! has her shares H1_r and H2_r. They need to compute shares of H3.
//! H3 = (H1_s + H1_r)*(H2_s + H2_r) = H1_s*H2_s + H1_s*H2_r + H1_r*H2_s +
//! H1_r*H2_r. Term 1 can be computed by S locally and term 4 can be
//! computed by R locally. Only terms 2 and 3 will be computed using
//! GHASH 2PC. R will obliviously request values for bits of H1_r and H2_r.
//! The XOR sum of all values which S will send back plus H1_r*H2_r will
//! become R's share of H3.
//!
//! When performing block multiplication in 2PC, Master holds the Y value and
//! Slave holds the X value. The Slave then computes the X table and masks it.

mod common;
pub mod errors;
pub mod master;
pub mod slave;
mod utils;

use errors::*;
use std::collections::BTreeMap;

/// MXTableFull is masked XTable which Slave has at the beginning of OT.
/// MXTableFull must not be revealed to Master.
type MXTableFull = Vec<[u128; 2]>;
/// MXTable is a masked x table which Master will end up having after OT.
type MXTable = Vec<u128>;
/// YBits are Master's bits of Y in big-endian. Based on these bits
/// Master will send MXTable via OT.
/// The convention for the returned Y bits:
/// A) powers are in an ascending order: first powers[1], then powers[2] etc.
/// B) bits of each power are in big-endian.
type YBits = Vec<bool>;

pub trait MasterCore {
    /// Returns choice bits for Oblivious Transfer.
    /// While is_complete() returns false, next_request() must be called
    /// followed by process_response().
    fn next_request(&mut self) -> Result<Vec<bool>, GhashError>;

    /// process_response() will be invoked by the Oblivious Transfer impl. It
    /// receives masked X tables acc. to our choice bits in next_request().
    fn process_response(&mut self, response: &Vec<u128>) -> Result<(), GhashError>;

    /// Returns true when the protocol is complete.
    fn is_complete(&mut self) -> bool;

    /// Returns our GHASH share.
    fn finalize(&mut self) -> Result<u128, GhashError>;

    /// Returns the amount of Oblivious Transfer instances needed to complete
    /// the protocol. The purpose is to inform the OT layer.
    fn calculate_ot_count(&mut self) -> usize;

    /// Exports powers of the GHASH key obtained at the current stage of the
    /// protocol.
    fn export_powers(&mut self) -> BTreeMap<u16, u128>;
}

pub trait SlaveCore {
    /// Returns the full masked X table which must NOT be passed to Master. It
    /// must be consumed by the Oblivious Transfer impl.
    fn process_request(&mut self) -> Result<Vec<[u128; 2]>, GhashError>;

    /// Returns true when the protocol is complete.
    fn is_complete(&mut self) -> bool;

    /// Returns our GHASH share.
    fn finalize(&mut self) -> Result<u128, GhashError>;

    /// Returns the amount of Oblivious Transfer instances needed to complete
    /// the protocol. The purpose is to inform the OT layer.
    fn calculate_ot_count(&mut self) -> usize;

    /// Exports powers of the GHASH key obtained at the current stage of the
    /// protocol.
    fn export_powers(&mut self) -> BTreeMap<u16, u128>;
}

#[cfg(test)]
mod tests {
    use super::{
        errors::GhashError, master::GhashMaster, slave::GhashSlave, utils::block_mult, MasterCore,
        SlaveCore,
    };
    use ghash_rc::{
        universal_hash::{NewUniversalHash, UniversalHash},
        GHash,
    };
    use rand::{prelude::ThreadRng, thread_rng, Rng};
    use std::convert::TryInto;

    #[test]
    // test only round 1
    fn test_round1() {
        let block_count = 3;
        let (h, mut slave, mut master, blocks) = ghash_setup(block_count);
        run_round(&mut slave, &mut master).unwrap();
        let ghash = finalize(&mut slave, &mut master);
        assert_eq!(ghash, rust_crypto_ghash(h, &blocks));
        assert!(master.is_complete());
        assert!(slave.is_complete());
    }

    #[test]
    // test state after rounds 1,2 (but before block aggregation)
    fn test_round12_before_block_aggregation() {
        let block_count = 30;
        let (h, mut slave, mut master, _blocks) = ghash_setup(block_count);
        run_round(&mut slave, &mut master).unwrap();
        run_round(&mut slave, &mut master).unwrap();

        let s_powers = slave.export_powers();
        let r_powers = master.export_powers();
        let all_s_keys: Vec<u16> = s_powers.keys().cloned().collect();
        let all_r_keys: Vec<u16> = r_powers.keys().cloned().collect();
        let expected_keys = vec![1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28];
        let exp_powers = compute_expected_powers(h, block_count as u16);

        assert_eq!(all_s_keys, expected_keys);
        assert_eq!(all_r_keys, expected_keys);
        // compare shares of powers against expected powers
        for key in expected_keys.iter() {
            assert_eq!(
                exp_powers[*key as usize],
                *s_powers.get(key).unwrap() ^ *r_powers.get(key).unwrap()
            );
        }
        assert!(!master.is_complete());
        assert!(!slave.is_complete());
    }

    #[test]
    // test rounds 1,2,4
    fn test_round124() {
        let block_count = 30;
        let (h, mut slave, mut master, blocks) = ghash_setup(block_count);
        run_round(&mut slave, &mut master).unwrap();
        run_round(&mut slave, &mut master).unwrap();
        run_round(&mut slave, &mut master).unwrap();
        let ghash = finalize(&mut slave, &mut master);
        assert_eq!(ghash, rust_crypto_ghash(h, &blocks));
        assert!(master.is_complete());
        assert!(slave.is_complete());
    }

    #[test]
    // test rounds 1,2,3,4
    fn test_round1234() {
        let block_count = 340;
        let (h, mut slave, mut master, blocks) = ghash_setup(block_count);
        run_round(&mut slave, &mut master).unwrap();
        run_round(&mut slave, &mut master).unwrap();
        run_round(&mut slave, &mut master).unwrap();
        run_round(&mut slave, &mut master).unwrap();
        let ghash = finalize(&mut slave, &mut master);
        assert_eq!(ghash, rust_crypto_ghash(h, &blocks));
        assert!(master.is_complete());
        assert!(slave.is_complete());
    }

    #[test]
    // test export_powers() after round 1
    fn test_export_powers() {
        let block_count = 340;
        let (h, mut slave, mut master, blocks) = ghash_setup(block_count);
        run_round(&mut slave, &mut master).unwrap();
        let powers_s = slave.export_powers();
        let powers_r = master.export_powers();
        // we only have 4 consecutive powers 1,2,3,4 after round 1
        // we compute ghash for only the first 4 blocks
        let mut ghash_share_s = 0u128;
        for i in 0..4 {
            ghash_share_s ^= block_mult(*powers_s.get(&(4 - i)).unwrap(), blocks[i as usize]);
        }
        let mut ghash_share_r = 0u128;
        for i in 0..4 {
            ghash_share_r ^= block_mult(*powers_r.get(&(4 - i)).unwrap(), blocks[i as usize]);
        }
        let ghash = ghash_share_s ^ ghash_share_r;
        assert_eq!(ghash, rust_crypto_ghash(h, &blocks[0..4].to_vec()));
        assert!(!master.is_complete());
        assert!(!slave.is_complete());
    }

    #[test]
    // test OT count against hard-coded values and also double-check against
    // the actual amount of Y bits which the Master requested.
    fn test_calculate_ot_count() {
        let block_counts = vec![3, 19, 200, 1026];
        // expected amount of 2PC block multiplications
        let expected = vec![2, 8, 44, 96];

        for i in 0..block_counts.len() {
            let block_count = block_counts[i];
            let (_, mut slave, mut master, _) = ghash_setup(block_count);
            let mut ybits_count = 0;
            while !master.is_complete() {
                let req = master.next_request().unwrap();
                ybits_count += req.len();
                let resp = slave.process_request().unwrap();
                let masked_xtable = simulate_ot(&req, &resp);
                master.process_response(&masked_xtable).unwrap();
            }
            let ot_count = master.calculate_ot_count();
            assert!(ot_count == expected[i] * 128);
            assert!(ot_count == ybits_count);
        }
    }

    fn finalize(sender: &mut GhashSlave<ThreadRng>, receiver: &mut GhashMaster) -> u128 {
        let sender_ghash_share = sender.finalize().unwrap();
        let receiver_ghash_share = receiver.finalize().unwrap();
        receiver_ghash_share ^ sender_ghash_share
    }

    fn ghash_setup(block_count: usize) -> (u128, GhashSlave<ThreadRng>, GhashMaster, Vec<u128>) {
        let mut rng = thread_rng();
        // h is ghash key
        let h: u128 = rng.gen();
        // h_s is sender's XOR share of h
        let h_s: u128 = rng.gen();
        // h_r is receiver's XOR share of h
        let h_r: u128 = h ^ h_s;

        let blocks: Vec<u128> = random_blocks(block_count);
        let sender = GhashSlave::new(rng, h_s, blocks.clone()).unwrap();
        let receiver = GhashMaster::new(h_r, blocks.clone()).unwrap();
        (h, sender, receiver, blocks)
    }

    fn random_blocks(block_count: usize) -> Vec<u128> {
        let mut rng = thread_rng();
        let mut blocks: Vec<u128> = Vec::new();
        for _i in 0..block_count {
            blocks.push(rng.gen());
        }
        blocks
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

    // run_round runs the next round
    fn run_round(
        sender: &mut GhashSlave<ThreadRng>,
        receiver: &mut GhashMaster,
    ) -> Result<(), GhashError> {
        let receiver_bits = receiver.next_request()?;
        let masked_xtable_full = sender.process_request()?;
        let masked_xtable = simulate_ot(&receiver_bits, &masked_xtable_full);
        receiver.process_response(&masked_xtable)?;
        Ok(())
    }

    // normally Master will send his bits via OT to get only 1 out of 2 values
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
