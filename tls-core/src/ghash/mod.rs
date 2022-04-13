mod receiver;
mod sender;
mod utils;

#[cfg(test)]
mod tests {
    use crate::ghash::{receiver::GhashReceiver, sender::GhashSender};
    use ghash::{
        universal_hash::{NewUniversalHash, UniversalHash},
        GHash,
    };
    use rand::{thread_rng, Rng};

    #[test]
    fn test_ghash_against_rustcrypto() {
        let mut rng1 = thread_rng();
        let rng2 = thread_rng();
        // h is ghash key
        let h: u128 = rng1.gen();
        // h_s is sender's XOR share of h
        let h_s: u128 = rng1.gen();
        // h_r is receiver's XOR share of h
        let h_r: u128 = h ^ h_s;
        // x1,x2,x3 are 1st, 2nd, 3rd blocks to be ghashed
        let x1: u128 = rng1.gen();
        let x2: u128 = rng1.gen();
        let x3: u128 = rng1.gen();

        let mut sender = GhashSender::new(rng1, h_s, vec![x1, x2, x3]);
        let mut receiver = GhashReceiver::new(rng2, h_r, vec![x1, x2, x3]);
        let receiver_bits = receiver.bits_for_finished();
        let (masked_xtable_full, sender_ghash_share) = sender.masked_xtable_for_finished();

        // normally receiver will send his bits via OT to get only 1 out of 2 values
        // for each row of masked xtable. Here we simulate OT behaviour.
        let mut masked_xtable: Vec<u128> = Vec::new();
        for i in 0..masked_xtable_full.len() {
            masked_xtable.push(masked_xtable_full[i][receiver_bits[i] as usize]);
        }

        // continue after OT is completed
        let receiver_ghash_share = receiver.process_xtable_for_finished(masked_xtable);
        let ghash_result = sender_ghash_share ^ receiver_ghash_share;

        // compute the same with RustCrypto
        let mut ghash = GHash::new(&h.to_be_bytes().into());
        ghash.update(&x1.to_be_bytes().into());
        ghash.update(&x2.to_be_bytes().into());
        ghash.update(&x3.to_be_bytes().into());
        let expected = ghash.finalize();

        assert_eq!(ghash_result.to_be_bytes(), expected.into_bytes().as_slice());
    }

    #[test]
    fn test_ghash_round1() {
        // test that the shares of powers for round 1 were computed correctly
        let mut rng1 = thread_rng();
        let rng2 = thread_rng();
        // h is ghash key
        let h: u128 = rng1.gen();
        // h_s is sender's XOR share of h
        let h_s: u128 = rng1.gen();
        // h_r is receiver's XOR share of h
        let h_r: u128 = h ^ h_s;
        let blockCount = 15;
        let blocks: Vec<u128> = vec![rng1.gen(); blockCount];

        let mut sender = GhashSender::new(rng1, h_s, blocks.clone());
        let mut receiver = GhashReceiver::new(rng2, h_r, blocks.clone());
        let receiver_bits = receiver.bits_for_round(1);
        let xtables_full = sender.step1();
        assert!(receiver_bits.len() == xtables_full.len());

        // normally receiver will send his bits via OT to get only 1 out of 2 values
        // for each row of masked xtable. Here we simulate OT behaviour.
        let mut xtables: Vec<Vec<u128>> = Vec::new();
        for i in 0..xtables_full.len() {
            let mut xtable: Vec<u128> = Vec::new();
            for j in 0..128 {
                let choice = receiver_bits[i][j] as usize;
                xtable.push(xtables_full[i][j][choice]);
            }
            xtables.push(xtable);
        }

        receiver.process_xtables_for_round(xtables, 1);
    }
}
