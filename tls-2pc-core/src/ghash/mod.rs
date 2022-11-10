//! This module implements the AES-GCM's GHASH function in a secure two-party computation (2PC)
//! setting using 1-out-of-2 Oblivious Transfer (OT). The parties start with their secret XOR
//! shares of H (the GHASH key) and at the end each gets their XOR share of the GHASH output. The

//!
//! At first we will convert the XOR (additive) share of `H`, into a multiplicative share. This
//! allows us to compute all the necessary powers of `H^n` locally. Then each of these
//! multiplicative shares will be converted back into additive shares. This way, we can batch
//! nearly all oblivious transfers and reduce the round complexity of the protocol.
//!
//! On the whole, we need a single additive-to-multiplicative (A2M) and `n`, which is the number of
//! blocks of ciphertext, multiplicative-to-additive (M2A) conversions. Finally, having
//! additive shares of `H^n` for all needed `n`, we can compute an additive share of the MAC.

mod receiver;
mod sender;
use crate::msgs::ghash::{
    ReceiverAddChoice, ReceiverMulPowerChoices, SenderAddSharing, SenderMulSharings,
};
use gf2_128::{compute_product_repeated, mul, AddShare, MulShare};
use thiserror::Error;

pub use {receiver::GhashReceiver, sender::GhashSender};

#[derive(Clone, Debug)]
pub struct Init {
    add_share: AddShare,
}

#[derive(Clone, Debug)]
pub struct Intermediate {
    mul_shares: Vec<MulShare>,
    cached_add_shares: Vec<AddShare>,
}

#[derive(Clone, Debug)]
pub struct Finalized {
    mul_shares: Vec<MulShare>,
    add_shares: Vec<AddShare>,
}

#[derive(Debug, Error)]
pub enum GhashError {
    #[error("Unable to compute MAC for empty ciphertext")]
    NoCipherText,
}

/// Computes missing powers of multiplication shares of the hashkey
///
/// Checks if depending on the number of add_shares or ciphertext blocks
/// we need more multiplicative sharings and computes them.
///
/// * `shares` - multiplicative shares already present
/// * `needed` - how many powers we need including odd and even
fn compute_missing_mul_shares(shares: &mut Vec<u128>, needed: usize) {
    let needed_odd_powers: usize = needed / 2 + (needed & 1);
    let present_odd_powers = shares.len();
    let difference = needed_odd_powers - present_odd_powers;

    if difference > 0 {
        let h_squared = mul(shares[0], shares[0]);
        compute_product_repeated(shares, h_squared, difference);
    }
}

/// Computes new additive shares from odd additive shares
///
/// This function implements the logic required for free squaring. Every additive share, which is
/// an even power of `H` can be computed without an OT interaction by using `H^(n/2)` for building
/// `H^n`.
///
/// * `new_add_odd_shares` - odd additive shares we get as a result from doing an OT on odd
///                          multiplicative shares
/// * `add_shares`         - all powers of additive shares (even and odd) we need for the MAC
fn compute_new_add_shares(new_add_odd_shares: &[AddShare], add_shares: &mut Vec<AddShare>) {
    for (odd_share, current_power) in new_add_odd_shares.iter().zip(add_shares.len()..) {
        if current_power & 1 == 1 {
            // if the next required share is odd, we just add it
            add_shares.push(*odd_share)
        } else {
            // else we compute `H^n` from `H^(n/2)`
            let mut base_share = add_shares[current_power >> 1].inner();
            base_share = mul(base_share, base_share);
            add_shares.push(AddShare::new(base_share));
        }
    }
}

#[cfg(test)]
mod tests {
    use ghash_rc::universal_hash::NewUniversalHash;
    use ghash_rc::universal_hash::UniversalHash;
    use ghash_rc::GHash;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha12Rng;

    use super::*;

    #[test]
    fn test_ghash_product_sharing() {
        let mut rng = ChaCha12Rng::from_entropy();

        // The MAC key
        let h: u128 = rng.gen();
        let ciphertext = gen_ciphertext();

        let (sender, receiver) = setup_ghash_to_intermediate_state(h, ciphertext);

        // Product check
        assert_eq!(
            mul(
                sender.state().mul_shares[0].inner(),
                receiver.state().mul_shares[0].inner()
            ),
            h
        );
    }

    #[test]
    fn test_ghash_sum_sharing() {
        let mut rng = ChaCha12Rng::from_entropy();

        // The MAC key
        let h: u128 = rng.gen();
        let ciphertext = gen_ciphertext();

        let (sender, receiver) = setup_ghash_to_intermediate_state(h, ciphertext);
        let (sender, receiver) = ghash_to_finalized(sender, receiver);

        // Sum check for the first 2 powers `H` and `H^2`
        assert_eq!(
            sender.state().add_shares[0].inner() ^ receiver.state().add_shares[0].inner(),
            h
        );
        assert_eq!(
            sender.state().add_shares[1].inner() ^ receiver.state().add_shares[1].inner(),
            mul(h, h)
        );
    }

    #[test]
    fn test_ghash_mac() {
        let mut rng = ChaCha12Rng::from_entropy();

        // The MAC key
        let h: u128 = rng.gen();
        let ciphertext = gen_ciphertext();

        let (sender, receiver) = setup_ghash_to_intermediate_state(h, ciphertext.clone());
        let (sender, receiver) = ghash_to_finalized(sender, receiver);

        assert_eq!(
            sender.generate_mac() ^ receiver.generate_mac(),
            ghash_reference_impl(h, ciphertext)
        );
    }

    #[test]
    fn test_ghash_change_ciphertext_short() {
        let mut rng = ChaCha12Rng::from_entropy();

        // The MAC key
        let h: u128 = rng.gen();
        let ciphertext = gen_ciphertext();

        let (sender, receiver) = setup_ghash_to_intermediate_state(h, ciphertext.clone());
        let (sender, receiver) = ghash_to_finalized(sender, receiver);

        let mut ciphertext_short: Vec<u128> = vec![0; ciphertext.len() / 2];
        ciphertext_short.iter_mut().for_each(|x| *x = rng.gen());

        let (sender, None) = sender.change_ciphertext(ciphertext_short.clone()) else {
            panic!("Expected None, but got Some(...)");
        };
        let receiver = receiver.change_ciphertext(ciphertext_short.clone());
        let receiver = receiver.into_add_powers(None);

        assert_eq!(
            sender.generate_mac() ^ receiver.generate_mac(),
            ghash_reference_impl(h, ciphertext_short)
        );
    }

    #[test]
    fn test_ghash_change_ciphertext_long() {
        let mut rng = ChaCha12Rng::from_entropy();

        // The MAC key
        let h: u128 = rng.gen();
        let ciphertext = gen_ciphertext();

        let (sender, receiver) = setup_ghash_to_intermediate_state(h, ciphertext.clone());
        let (sender, receiver) = ghash_to_finalized(sender, receiver);

        let mut ciphertext_long: Vec<u128> = vec![0; 2 * ciphertext.len()];
        ciphertext_long.iter_mut().for_each(|x| *x = rng.gen());

        let (sender, Some(sharing)) = sender.change_ciphertext(ciphertext_long.clone()) else {
            panic!("Expected Some(...), but got None");
        };
        let receiver = receiver.change_ciphertext(ciphertext_long.clone());

        // Do another OT because we have higher powers of `H` to compute
        let choices = receiver.choices();
        let chosen_inputs = ot_mock_batch(sharing.sender_mul_sharing, choices.unwrap().0);

        let receiver = receiver.into_add_powers(Some(chosen_inputs));

        assert_eq!(
            sender.generate_mac() ^ receiver.generate_mac(),
            ghash_reference_impl(h, ciphertext_long)
        );
    }

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

    fn gen_ciphertext() -> Vec<u128> {
        let mut rng = ChaCha12Rng::from_entropy();

        // Sample some ciphertext
        let ciphertext_len: usize = rng.gen_range(16..128);
        let mut ciphertext: Vec<u128> = vec![0_u128; ciphertext_len];
        ciphertext.iter_mut().for_each(|x| *x = rng.gen());
        ciphertext
    }

    fn ghash_reference_impl(h: u128, ciphertext: Vec<u128>) -> u128 {
        let mut ghash = GHash::new(&h.to_be_bytes().into());
        for el in ciphertext {
            ghash.update(&el.to_be_bytes().into());
        }
        let mac = ghash.finalize();
        u128::from_be_bytes(mac.into_bytes().try_into().unwrap())
    }

    fn setup_ghash_to_intermediate_state(
        hashkey: u128,
        ciphertext: Vec<u128>,
    ) -> (GhashSender<Intermediate>, GhashReceiver<Intermediate>) {
        let mut rng = ChaCha12Rng::from_entropy();

        // The additive sharings of the MAC key to begin with
        let h1: u128 = rng.gen();
        let h2: u128 = hashkey ^ h1;

        let sender = GhashSender::new(h1, ciphertext.clone()).unwrap();
        let receiver = GhashReceiver::new(h2, ciphertext).unwrap();

        let (sender, sharing) = sender.compute_mul_powers();
        let choices = receiver.choices();

        let chosen_inputs = ot_mock(sharing.sender_add_sharing, choices.0);
        let receiver = receiver.compute_mul_powers(chosen_inputs);
        (sender, receiver)
    }

    fn ghash_to_finalized(
        sender: GhashSender<Intermediate>,
        receiver: GhashReceiver<Intermediate>,
    ) -> (GhashSender<Finalized>, GhashReceiver<Finalized>) {
        let (sender, sharing) = sender.into_add_powers();
        let choices = receiver.choices();

        let chosen_inputs = ot_mock_batch(sharing.sender_mul_sharing, choices.unwrap().0);
        let receiver = receiver.into_add_powers(Some(chosen_inputs));
        (sender, receiver)
    }
}
