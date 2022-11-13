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
mod types;
use gf2_128::{compute_product_repeated, mul, AddShare, MulShare};
use thiserror::Error;
pub use types::{
    ReceiverAddChoice, ReceiverAddShares, ReceiverMulChoices, ReceiverMulShare, SenderAddSharing,
    SenderMulSharing,
};

pub use {receiver::GhashReceiver, sender::GhashSender};

#[derive(Clone, Debug)]
/// Init state for Ghash protocol
///
/// This is before any OT has taken place
pub struct Init {
    add_share: AddShare,
}

#[derive(Clone, Debug)]
/// Intermediate state for Ghash protocol
///
/// This is when the additive share has been converted into a multiplicative share and all the
/// needed powers have been computed
pub struct Intermediate {
    odd_mul_shares: Vec<MulShare>,
    cached_add_shares: Vec<AddShare>,
}

/// Final state for Ghash protocol
///
/// This is when each party has can compute a final share of the MAC, because both now have
/// additive shares of all the powers of `H`
#[derive(Clone, Debug)]
pub struct Finalized {
    odd_mul_shares: Vec<MulShare>,
    add_shares: Vec<AddShare>,
}

#[derive(Debug, Error)]
pub enum GhashError {
    #[error("Invalid maximum hashkey power")]
    ZeroHashkeyPower,
    #[error("Ciphertext too long")]
    InvalidCiphertextLength,
}

/// Computes missing powers of multiplication shares of the hashkey
///
/// Checks if depending on the number of `needed` shares, we need more multiplicative shares and
/// computes them. Notice that we need only odd multiplicative shares for the OT, because we can
/// reconstruct even additive shares from odd additive shares, which we call free squaring.
///
/// * `shares` - multiplicative shares already present
/// * `needed` - how many powers we need including odd and even
fn compute_missing_mul_shares(shares: &mut Vec<u128>, needed: usize) {
    let needed_odd_powers: usize = needed / 2 + (needed & 1);
    let present_odd_powers = shares.len();
    let difference = needed_odd_powers as i32 - present_odd_powers as i32;

    if difference > 0 {
        let h_squared = mul(shares[0], shares[0]);
        compute_product_repeated(shares, h_squared, difference as usize);
    }
}

/// Computes new even additive shares from odd additive shares
///
/// This function implements the derivation of the even additive shares from odd additive shares,
/// which we refer to as free squaring. Every additive share, which is an even power of
/// `H` can be computed without an OT interaction by using `H^(n/2)` for building `H^n`.
///
/// * `new_add_odd_shares` - odd additive shares we get as a result from doing an OT on odd
///                          multiplicative shares
/// * `add_shares`         - all powers of additive shares (even and odd) we need for the MAC
fn compute_new_add_shares(new_add_odd_shares: &[AddShare], add_shares: &mut Vec<AddShare>) {
    for (odd_share, current_power) in new_add_odd_shares
        .iter()
        .zip((add_shares.len()..).step_by(2))
    {
        // add_shares always has an even number of shares so we simply add the next odd share
        add_shares.push(*odd_share);

        // now we need to compute the next even share and add it
        let mut base_share = add_shares[current_power >> 1].inner();
        base_share = mul(base_share, base_share);
        add_shares.push(AddShare::new(base_share));
    }
}

#[cfg(test)]
mod tests {
    use ghash_rc::universal_hash::{NewUniversalHash, UniversalHash};
    use ghash_rc::GHash;
    use mpc_core::Block;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha12Rng;

    use crate::msgs::ghash::{SenderAddEnvelope, SenderMulEnvelope};

    use super::*;

    #[test]
    fn test_ghash_product_sharing() {
        let mut rng = ChaCha12Rng::from_entropy();

        // The MAC key
        let h: u128 = rng.gen();
        let ciphertext = gen_u128_vec();
        let ciphertext_len = ciphertext.len();
        let number_of_powers_needed: usize = ciphertext_len / 2 + (ciphertext_len & 1);

        let (sender, receiver) = setup_ghash_to_intermediate_state(h, ciphertext_len);

        let mut powers_h = vec![h];
        compute_product_repeated(&mut powers_h, mul(h, h), number_of_powers_needed);

        // Length check
        assert_eq!(sender.state().odd_mul_shares.len(), number_of_powers_needed);
        assert_eq!(
            receiver.state().odd_mul_shares.len(),
            number_of_powers_needed
        );

        // Product check
        for (k, (sender_share, receiver_share)) in std::iter::zip(
            sender.state().odd_mul_shares.iter(),
            receiver.state().odd_mul_shares.iter(),
        )
        .enumerate()
        {
            assert_eq!(
                mul(sender_share.inner(), receiver_share.inner()),
                powers_h[k]
            );
        }
    }

    #[test]
    fn test_ghash_sum_sharing() {
        let mut rng = ChaCha12Rng::from_entropy();

        // The MAC key
        let h: u128 = rng.gen();
        let ciphertext = gen_u128_vec();
        let ciphertext_len = ciphertext.len();

        let (sender, receiver) = setup_ghash_to_intermediate_state(h, ciphertext_len);
        let (sender, receiver) = ghash_to_finalized(sender, receiver);

        let mut powers_h = vec![h];
        compute_product_repeated(&mut powers_h, h, ciphertext_len);

        // Length check
        assert_eq!(
            sender.state().add_shares.len(),
            ciphertext_len + (ciphertext_len & 1)
        );
        assert_eq!(
            receiver.state().add_shares.len(),
            ciphertext_len + (ciphertext_len & 1)
        );

        // Sum check
        for k in 0..ciphertext_len {
            assert_eq!(
                sender.state().add_shares[k].inner() ^ receiver.state().add_shares[k].inner(),
                powers_h[k]
            );
        }
    }

    #[test]
    fn test_ghash_mac() {
        let mut rng = ChaCha12Rng::from_entropy();

        // The MAC key
        let h: u128 = rng.gen();
        let ciphertext = gen_u128_vec();

        let (sender, receiver) = setup_ghash_to_intermediate_state(h, ciphertext.len());
        let (sender, receiver) = ghash_to_finalized(sender, receiver);

        assert_eq!(
            sender.generate_mac(&ciphertext).unwrap() ^ receiver.generate_mac(&ciphertext).unwrap(),
            ghash_reference_impl(h, ciphertext)
        );
    }

    #[test]
    fn test_ghash_change_ciphertext_short() {
        let mut rng = ChaCha12Rng::from_entropy();

        // The MAC key
        let h: u128 = rng.gen();
        let ciphertext = gen_u128_vec();

        let (sender, receiver) = setup_ghash_to_intermediate_state(h, ciphertext.len());
        let (sender, receiver) = ghash_to_finalized(sender, receiver);

        let mut ciphertext_short: Vec<u128> = vec![0; ciphertext.len() / 2];
        ciphertext_short.iter_mut().for_each(|x| *x = rng.gen());

        let (sender, None) = sender.change_max_hashkey(ciphertext_short.len()) else {
            panic!("Expected None, but got Some(...)");
        };
        let receiver = receiver.change_max_hashkey(ciphertext_short.len());
        let receiver = receiver.into_add_powers(None);

        assert_eq!(
            sender.generate_mac(&ciphertext_short).unwrap()
                ^ receiver.generate_mac(&ciphertext_short).unwrap(),
            ghash_reference_impl(h, ciphertext_short)
        );
    }

    #[test]
    fn test_ghash_change_ciphertext_long() {
        let mut rng = ChaCha12Rng::from_entropy();

        // The MAC key
        let h: u128 = rng.gen();
        let ciphertext = gen_u128_vec();

        let (sender, receiver) = setup_ghash_to_intermediate_state(h, ciphertext.len());
        let (sender, receiver) = ghash_to_finalized(sender, receiver);

        let mut ciphertext_long: Vec<u128> = vec![0; 2 * ciphertext.len()];
        ciphertext_long.iter_mut().for_each(|x| *x = rng.gen());

        let (sender, Some(sharing)) = sender.change_max_hashkey(ciphertext_long.len()) else {
            panic!("Expected Some(...), but got None");
        };
        let receiver = receiver.change_max_hashkey(ciphertext_long.len());

        // Do another OT because we have higher powers of `H` to compute
        let choices = receiver.choices().unwrap();

        let sender_mul_envelope: SenderMulEnvelope = sharing.into();
        let bool_choices: Vec<bool> = choices.into();

        let chosen_inputs = ot_mock_batch(sender_mul_envelope.sender_mul_envelope, &bool_choices);
        let receiver = receiver.into_add_powers(Some(chosen_inputs.into()));

        assert_eq!(
            sender.generate_mac(&ciphertext_long).unwrap()
                ^ receiver.generate_mac(&ciphertext_long).unwrap(),
            ghash_reference_impl(h, ciphertext_long)
        );
    }

    #[test]
    fn test_compute_missing_mul_shares() {
        let mut rng = ChaCha12Rng::from_entropy();
        let h: u128 = rng.gen();
        let mut powers: Vec<u128> = vec![h];
        compute_product_repeated(&mut powers, mul(h, h), rng.gen_range(16..128));

        let powers_len = powers.len();
        let needed = rng.gen_range(1..256);

        compute_missing_mul_shares(&mut powers, needed);

        // Check length
        if needed / 2 + (needed & 1) <= powers_len {
            assert_eq!(powers.len(), powers_len);
        } else {
            assert_eq!(powers.len(), needed / 2 + (needed & 1))
        }

        // Check shares
        let first = *powers.first().unwrap();
        let factor = mul(first, first);

        let mut expected = first;
        for share in powers.iter() {
            assert_eq!(*share, expected);
            expected = mul(expected, factor);
        }
    }

    #[test]
    fn test_compute_new_add_shares() {
        let mut rng = ChaCha12Rng::from_entropy();

        let new_add_odd_shares: Vec<AddShare> = gen_u128_vec()
            .iter_mut()
            .map(|x| AddShare::new(*x))
            .collect();
        let mut add_shares: Vec<AddShare> = gen_u128_vec()
            .iter_mut()
            .map(|x| AddShare::new(*x))
            .collect();

        // We have the invariant that len of add_shares is always even
        if add_shares.len() & 1 == 1 {
            add_shares.push(AddShare::new(rng.gen()));
        }

        let original_len = add_shares.len();

        compute_new_add_shares(&new_add_odd_shares, &mut add_shares);

        // Check new length
        assert_eq!(
            add_shares.len(),
            original_len + 2 * new_add_odd_shares.len()
        );

        // Check odd shares
        for (k, l) in (original_len..add_shares.len())
            .step_by(2)
            .zip(0..original_len)
        {
            assert_eq!(add_shares[k].inner(), new_add_odd_shares[l].inner());
        }

        // Check even shares
        for k in (original_len + 1..add_shares.len()).step_by(2) {
            assert_eq!(
                add_shares[k].inner(),
                mul(add_shares[k / 2].inner(), add_shares[k / 2].inner())
            );
        }
    }

    fn ot_mock(envelope: [Block; 2], choice: bool) -> Block {
        if choice {
            envelope[1]
        } else {
            envelope[0]
        }
    }

    fn ot_mock_batch(envelopes: Vec<[Block; 2]>, choices: &[bool]) -> Vec<Block> {
        let mut out: Vec<Block> = vec![];

        for (envelope, choice) in envelopes.into_iter().zip(choices.iter()) {
            out.push(ot_mock(envelope, *choice));
        }
        out
    }

    fn gen_u128_vec() -> Vec<u128> {
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
        max_hashkey_power: usize,
    ) -> (GhashSender<Intermediate>, GhashReceiver<Intermediate>) {
        let mut rng = ChaCha12Rng::from_entropy();

        // The additive sharings of the MAC key to begin with
        let h1: u128 = rng.gen();
        let h2: u128 = hashkey ^ h1;

        let sender = GhashSender::new(h1, max_hashkey_power).unwrap();
        let receiver = GhashReceiver::new(h2, max_hashkey_power).unwrap();

        let (sender, sharing) = sender.compute_mul_powers();
        let choices = receiver.choices();

        let sender_add_envelope: SenderAddEnvelope = sharing.into();
        let bool_choices: Vec<bool> = choices.into();

        let chosen_inputs = ot_mock_batch(sender_add_envelope.sender_add_envelope, &bool_choices);
        let receiver = receiver.compute_mul_powers(chosen_inputs.into());
        (sender, receiver)
    }

    fn ghash_to_finalized(
        sender: GhashSender<Intermediate>,
        receiver: GhashReceiver<Intermediate>,
    ) -> (GhashSender<Finalized>, GhashReceiver<Finalized>) {
        let (sender, sharing) = sender.into_add_powers();
        let choices = receiver.choices().unwrap();

        let sender_mul_envelope: SenderMulEnvelope = sharing.into();
        let bool_choices: Vec<bool> = choices.into();

        let chosen_inputs = ot_mock_batch(sender_mul_envelope.sender_mul_envelope, &bool_choices);
        let receiver = receiver.into_add_powers(Some(chosen_inputs.into()));
        (sender, receiver)
    }
}
