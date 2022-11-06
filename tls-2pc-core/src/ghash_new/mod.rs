//! This module implements the AES-GCM's GHASH function in a secure two-party computation (2PC)
//! setting using 1-out-of-2 Oblivious Transfer (OT). The parties start with their secret XOR
//! shares of H (the GHASH key) and at the end each gets their XOR share of the GHASH output. The
//! method is decribed here <https://tlsnotary.org/how_it_works#section4>.
//!
//! At first we will convert the XOR (additive) share of `H`, into a multiplicative share. This
//! allows us to compute all the necessary powers of `H^n` locally. Then each of these
//! multiplicative shares will be converted back into additive shares. This way, we can batch
//! nearly all the oblivious transfers, which are needed per conversion, and reduce the round
//! complexity of the protocol.
//!
//! On the whole, we need a single additive-to-multiplicative (A2M) and `n`, which is the number of
//! blocks of the ciphertext, multiplicative-to-additive (M2A) conversions. Finally, having
//! additive shares of `H^n` for all needed `n`, we can compute an additive share of the MAC.

mod receiver;
mod sender;
use gf2_128::{compute_powers, mul, AddShare, MaskedPartialValue, MulShare};
pub use {receiver::GhashReceiver, sender::GhashSender};

#[cfg(test)]
mod tests {
    use ghash_rc::universal_hash::NewUniversalHash;
    use ghash_rc::universal_hash::UniversalHash;
    use ghash_rc::GHash;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha12Rng;

    use super::*;

    fn ot_mock(envelope: ([u128; 128], [u128; 128]), choice: u128) -> [u128; 128] {
        let mut out = [0_u128; 128];
        for (k, number) in out.iter_mut().enumerate() {
            let bit = (choice >> k) & 1;
            *number = (bit * envelope.1[k]) ^ ((bit ^ 1) * envelope.0[k]);
        }
        out
    }

    fn ot_mock_batch(
        envelopes: Vec<([u128; 128], [u128; 128])>,
        choices: Vec<u128>,
    ) -> Vec<[u128; 128]> {
        let mut ot_batch_outcome: Vec<[u128; 128]> = vec![];

        for (k, envelope) in envelopes.iter().enumerate() {
            let out = ot_mock(*envelope, choices[k]);
            ot_batch_outcome.push(out);
        }
        ot_batch_outcome
    }

    #[test]
    fn test_ghash() {
        let mut rng = ChaCha12Rng::from_entropy();

        // The MAC key
        let h: u128 = rng.gen();

        // Sample some ciphertext
        let cipher_text_len: usize = rng.gen_range(1..128);
        let mut ciphertext: Vec<u128> = vec![0_u128; cipher_text_len];
        ciphertext.iter_mut().for_each(|x| *x = rng.gen());

        // The additive sharings of the MAC key
        let h1 = rng.gen();
        let h2 = h ^ h1;

        // Compute Ghash in 2PC with mocked OT
        let sender = GhashSender::new(h1, ciphertext.clone());
        let receiver = GhashReceiver::new(h2, ciphertext.clone());

        let (sender, sharing) = sender.compute_mul_powers();
        let choices = receiver.choices();

        let chosen_inputs = ot_mock((sharing.0, sharing.1), choices);
        let receiver = receiver.compute_mul_powers(chosen_inputs);

        let (sender, sharing) = sender.into_add_powers();
        let choices = receiver.choices();

        let sharing: Vec<([u128; 128], [u128; 128])> =
            sharing.iter().map(|el| (el.0, el.1)).collect();

        let chosen_inputs = ot_mock_batch(sharing, choices);
        let receiver = receiver.into_add_powers(chosen_inputs);

        //Compute Ghash with crate
        let mut ghash = GHash::new(&h.to_be_bytes().into());
        for el in ciphertext {
            ghash.update(&el.to_be_bytes().into());
        }
        let expected_mac = ghash.finalize();

        assert_eq!(
            sender.into_mac() ^ receiver.into_mac(),
            u128::from_be_bytes(expected_mac.into_bytes().try_into().unwrap())
        );
    }
}
