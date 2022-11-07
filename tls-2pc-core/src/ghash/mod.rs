//! This module implements the AES-GCM's GHASH function in a secure two-party computation (2PC)
//! setting using 1-out-of-2 Oblivious Transfer (OT). The parties start with their secret XOR
//! shares of H (the GHASH key) and at the end each gets their XOR share of the GHASH output. The
//! method is described here <https://tlsnotary.org/how_it_works#section4>.
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
use crate::msgs::ghash::{
    ReceiverAddChoice, ReceiverMulPowerChoices, SenderAddSharing, SenderMulPowerSharings,
};
use gf2_128::{compute_powers, mul, AddShare, MaskedPartialValue, MulShare};
use thiserror::Error;

pub use {receiver::GhashReceiver, sender::GhashSender};

#[derive(Clone, Debug)]
pub struct Init {
    pub(crate) add_share: AddShare,
}

#[derive(Clone, Debug)]
pub struct Intermediate {
    pub(crate) mul_shares: Vec<MulShare>,
    pub(crate) cached_add_shares: Vec<AddShare>,
}

#[derive(Clone, Debug)]
pub struct Finalized {
    pub(crate) mul_shares: Vec<MulShare>,
    pub(crate) add_shares: Vec<AddShare>,
}

#[derive(Debug, Error)]
pub enum GhashError {
    #[error("Unable to compute MAC for empty ciphertext")]
    NoCipherText,
    #[error("The provided input is insufficient for building the missing shares")]
    InsufficientInput,
}

fn attach_missing_mul_powers(mul_powers: &mut Vec<MulShare>, missing: usize) {
    // Compute the needed higher powers of H
    let mut higher_powers = vec![];
    for _ in 0..missing {
        let h = mul_powers[1].inner();
        let last_power = mul_powers.last().unwrap().inner();

        let new_mul_share = MulShare::new(mul(h, last_power));
        higher_powers.push(new_mul_share);
    }
    mul_powers.extend_from_slice(&higher_powers);
}

#[cfg(test)]
mod tests {
    use ghash_rc::universal_hash::NewUniversalHash;
    use ghash_rc::universal_hash::UniversalHash;
    use ghash_rc::GHash;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha12Rng;

    use super::*;

    fn ot_mock(envelope: MaskedPartialValue, choice: u128) -> [u128; 128] {
        let mut out = [0_u128; 128];
        for (k, number) in out.iter_mut().enumerate() {
            let bit = (choice >> k) & 1;
            *number = (bit * envelope.1[k]) ^ ((bit ^ 1) * envelope.0[k]);
        }
        out
    }

    fn ot_mock_batch(envelopes: Vec<MaskedPartialValue>, choices: Vec<u128>) -> Vec<[u128; 128]> {
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
        let ciphertext_len: usize = rng.gen_range(2..128);
        let mut ciphertext: Vec<u128> = vec![0_u128; ciphertext_len];
        ciphertext.iter_mut().for_each(|x| *x = rng.gen());

        // The additive sharings of the MAC key to begin with
        let h1: u128 = rng.gen();
        let h2: u128 = h ^ h1;

        // Compute Ghash in 2PC with mocked OT
        // 1. Get a multiplicative sharing of H
        let sender = GhashSender::new(h1, ciphertext.clone()).unwrap();
        let receiver = GhashReceiver::new(h2, ciphertext.clone()).unwrap();

        let (sender, sharing) = sender.compute_mul_powers();
        let choices = receiver.choices();

        let chosen_inputs = ot_mock(*sharing.0, choices.0);
        let receiver = receiver.compute_mul_powers(chosen_inputs);

        // Product check
        assert_eq!(
            mul(
                sender.state().mul_shares[1].inner(),
                receiver.state().mul_shares[1].inner()
            ),
            h
        );

        // 2. Get additive sharings of all the powers of H
        let (sender, sharing) = sender.into_add_powers();
        let choices = receiver.choices();

        let chosen_inputs = ot_mock_batch(sharing.0, choices.unwrap().0);
        let receiver = receiver.into_add_powers(Some(chosen_inputs));

        // Sum check for the first 2 powers `H` and `H^2`
        assert_eq!(
            sender.state().add_shares[1].inner() ^ receiver.state().add_shares[1].inner(),
            h
        );
        assert_eq!(
            sender.state().add_shares[2].inner() ^ receiver.state().add_shares[2].inner(),
            mul(h, h)
        );

        // Compare to Ghash computation from crate
        let mut ghash = GHash::new(&h.to_be_bytes().into());
        for el in ciphertext {
            ghash.update(&el.to_be_bytes().into());
        }
        let expected_mac = ghash.finalize();

        assert_eq!(
            sender.generate_mac() ^ receiver.generate_mac(),
            u128::from_be_bytes(expected_mac.into_bytes().try_into().unwrap())
        );
    }

    #[test]
    fn test_ghash_change_ciphertext() {
        let mut rng = ChaCha12Rng::from_entropy();

        // The MAC key
        let h: u128 = rng.gen();

        // Sample some ciphertext
        let ciphertext_len: usize = rng.gen_range(2..128);
        let mut ciphertext: Vec<u128> = vec![0_u128; ciphertext_len];
        ciphertext.iter_mut().for_each(|x| *x = rng.gen());

        // The additive sharings of the MAC key to begin with
        let h1: u128 = rng.gen();
        let h2: u128 = h ^ h1;

        // Compute Ghash in 2PC with mocked OT
        // 1. Get a multiplicative sharing of H
        let sender = GhashSender::new(h1, ciphertext.clone()).unwrap();
        let receiver = GhashReceiver::new(h2, ciphertext.clone()).unwrap();

        let (sender, sharing) = sender.compute_mul_powers();
        let choices = receiver.choices();

        let chosen_inputs = ot_mock(*sharing.0, choices.0);
        let receiver = receiver.compute_mul_powers(chosen_inputs);

        // 2. Get additive sharings of all the powers of H
        let (sender, sharing) = sender.into_add_powers();
        let choices = receiver.choices();

        let chosen_inputs = ot_mock_batch(sharing.0, choices.unwrap().0);
        let receiver = receiver.into_add_powers(Some(chosen_inputs));

        // 3. Generate MAC for original ciphertext
        let _mac_sender = sender.generate_mac();
        let _mac_receiver = receiver.generate_mac();

        // Compare to Ghash computation from crate
        let mut ghash = GHash::new(&h.to_be_bytes().into());
        for el in ciphertext {
            ghash.update(&el.to_be_bytes().into());
        }
        let expected_mac = ghash.finalize();

        assert_eq!(
            sender.generate_mac() ^ receiver.generate_mac(),
            u128::from_be_bytes(expected_mac.into_bytes().try_into().unwrap())
        );

        // 4. Change ciphertext to a new longer ciphertext and generate MAC
        let ciphertext_len_long: usize = rng.gen_range(129..256);
        let mut ciphertext_long: Vec<u128> = vec![0_u128; ciphertext_len_long];
        ciphertext_long.iter_mut().for_each(|x| *x = rng.gen());

        let (sender, Some(sharing)) = sender.change_ciphertext(ciphertext_long.clone()) else {
            panic!("Expected Some(...), but got None");
        };
        let receiver = receiver.change_ciphertext(ciphertext_long.clone());
        let choices = receiver.choices();

        let chosen_inputs = ot_mock_batch(sharing.0, choices.unwrap().0);

        let receiver = receiver.into_add_powers(Some(chosen_inputs));

        // Compare to Ghash computation from crate
        let mut ghash = GHash::new(&h.to_be_bytes().into());
        for el in ciphertext_long {
            ghash.update(&el.to_be_bytes().into());
        }
        let expected_mac = ghash.finalize();

        assert_eq!(
            sender.generate_mac() ^ receiver.generate_mac(),
            u128::from_be_bytes(expected_mac.into_bytes().try_into().unwrap())
        );
    }
}
