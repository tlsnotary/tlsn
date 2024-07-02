//! This module implements the AES-GCM's GHASH function in a secure two-party computation (2PC)
//! setting. The parties start with their secret XOR shares of H (the GHASH key) and at the end
//! each gets their XOR share of the GHASH output. The method is described here:
//! <https://tlsnotary.org/how_it_works#section4>.
//!
//! At first we will convert the XOR (additive) share of `H`, into a multiplicative share. This
//! allows us to compute all the necessary powers of `H^n` locally. Note, that it is only required
//! to compute the odd multiplicative powers, because of free squaring. Then each of these
//! multiplicative shares will be converted back into additive shares. The even additive shares can
//! then locally be built by using the odd ones. This way, we can batch nearly all oblivious
//! transfers and reduce the round complexity of the protocol.
//!
//! On the whole, we need a single additive-to-multiplicative (A2M) and `n/2`, where `n` is the
//! number of blocks of message, multiplicative-to-additive (M2A) conversions. Finally, having
//! additive shares of `H^n` for all needed `n`, we can compute an additive share of the GHASH
//! output.

/// Contains the core logic for ghash.
mod core;

/// Contains the different states.
pub(crate) mod state;

pub(crate) use self::core::GhashCore;

use mpz_fields::{compute_product_repeated, gf2_128::Gf2_128};
use thiserror::Error;
use tracing::instrument;

#[derive(Debug, Error)]
pub(crate) enum GhashError {
    #[error("Message too long")]
    InvalidMessageLength,
}

/// Computes missing odd multiplicative shares of the hashkey powers.
///
/// Checks if depending on the number of `needed` shares, we need more odd multiplicative shares and
/// computes them. Notice that we only need odd multiplicative shares for the OT, because we can
/// derive even additive shares from odd additive shares, which we call free squaring.
///
/// # Arguments
///
/// * `present_odd_mul_shares`  - Multiplicative odd shares already present.
/// * `needed`                  - How many powers we need including odd and even.
#[instrument(level = "trace", skip(present_odd_mul_shares))]
fn compute_missing_mul_shares(present_odd_mul_shares: &mut Vec<Gf2_128>, needed: usize) {
    // Divide by 2 and round up.
    let needed_odd_powers: usize = needed / 2 + (needed & 1);
    let present_odd_len = present_odd_mul_shares.len();

    if needed_odd_powers > present_odd_len {
        let h_squared = present_odd_mul_shares[0] * present_odd_mul_shares[0];
        compute_product_repeated(
            present_odd_mul_shares,
            h_squared,
            needed_odd_powers - present_odd_len,
        );
    }
}

/// Computes new even (additive) shares from new odd (additive) shares and saves both the new odd shares
/// and the new even shares.
///
/// This function implements the derivation of even additive shares from odd additive shares,
/// which we refer to as free squaring. Every additive share of an even power of
/// `H` can be computed without an OT interaction by squaring the corresponding additive share
/// of an odd power of `H`, e.g. if we have a share of H^3, we can derive the share of H^6 by doing
/// (H^3)^2.
///
/// # Arguments
///
/// * `new_add_odd_shares` - New odd additive shares we got as a result of doing an OT on odd
///                          multiplicative shares.
/// * `add_shares`         - All additive shares (even and odd) we already have. This is a mutable
///                          reference to cached_add_shares in [crate::ghash::state::Intermediate].
#[instrument(level = "trace", skip_all)]
fn compute_new_add_shares(new_add_odd_shares: &[Gf2_128], add_shares: &mut Vec<Gf2_128>) {
    for (odd_share, current_odd_power) in new_add_odd_shares
        .iter()
        .zip((add_shares.len() + 1..).step_by(2))
    {
        // `add_shares` always have an even number of shares so we simply add the next odd share.
        add_shares.push(*odd_share);

        // Now we need to compute the next even share and add it.
        // Note that the n-th index corresponds to the (n+1)-th power, e.g. add_shares[4]
        // is the share of H^5.
        let mut base_share = add_shares[current_odd_power / 2];
        base_share = base_share * base_share;
        add_shares.push(base_share);
    }
}

#[cfg(test)]
mod tests {
    use generic_array::GenericArray;
    use ghash_rc::{
        universal_hash::{KeyInit, UniversalHash},
        GHash,
    };
    use mpz_core::Block;
    use mpz_fields::{gf2_128::Gf2_128, Field};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha12Rng;

    use super::{
        compute_missing_mul_shares, compute_new_add_shares, compute_product_repeated,
        state::{Finalized, Intermediate},
        GhashCore,
    };

    #[test]
    fn test_ghash_product_sharing() {
        let mut rng = ChaCha12Rng::from_seed([0; 32]);

        // The Ghash key.
        let h: Gf2_128 = rng.gen();
        let message = Block::random_vec(&mut rng, 10);
        let message_len = message.len();
        let number_of_powers_needed: usize = message_len / 2 + (message_len & 1);

        let (sender, receiver) = setup_ghash_to_intermediate_state(h, message_len);

        let mut powers_h = vec![h];
        compute_product_repeated(&mut powers_h, h * h, number_of_powers_needed);

        // Length check.
        assert_eq!(sender.state().odd_mul_shares.len(), number_of_powers_needed);
        assert_eq!(
            receiver.state().odd_mul_shares.len(),
            number_of_powers_needed
        );

        // Product check.
        for (k, (sender_share, receiver_share)) in std::iter::zip(
            sender.state().odd_mul_shares.iter(),
            receiver.state().odd_mul_shares.iter(),
        )
        .enumerate()
        {
            assert_eq!(*sender_share * *receiver_share, powers_h[k]);
        }
    }

    #[test]
    fn test_ghash_sum_sharing() {
        let mut rng = ChaCha12Rng::from_seed([0; 32]);

        // The Ghash key.
        let h: Gf2_128 = rng.gen();
        let message = Block::random_vec(&mut rng, 10);
        let message_len = message.len();

        let (sender, receiver) = setup_ghash_to_intermediate_state(h, message_len);
        let (sender, receiver) = ghash_to_finalized(sender, receiver);

        let mut powers_h = vec![h];
        compute_product_repeated(&mut powers_h, h, message_len);

        // Length check.
        assert_eq!(
            sender.state().add_shares.len(),
            message_len + (message_len & 1)
        );
        assert_eq!(
            receiver.state().add_shares.len(),
            message_len + (message_len & 1)
        );

        // Sum check.
        for k in 0..message_len {
            assert_eq!(
                sender.state().add_shares[k] + receiver.state().add_shares[k],
                powers_h[k]
            );
        }
    }

    #[test]
    fn test_ghash_output() {
        let mut rng = ChaCha12Rng::from_seed([0; 32]);

        // The Ghash key.
        let h: Gf2_128 = rng.gen();
        let message = Block::random_vec(&mut rng, 10);

        let (sender, receiver) = setup_ghash_to_intermediate_state(h, message.len());
        let (sender, receiver) = ghash_to_finalized(sender, receiver);

        let output = sender.finalize(&message).unwrap() ^ receiver.finalize(&message).unwrap();

        assert_eq!(
            output,
            ghash_reference_impl(h.to_inner().reverse_bits(), &message)
        );
    }

    #[test]
    fn test_ghash_change_message_short() {
        let mut rng = ChaCha12Rng::from_seed([0; 32]);

        // The Ghash key.
        let h: Gf2_128 = rng.gen();
        let message = Block::random_vec(&mut rng, 10);

        let (sender, receiver) = setup_ghash_to_intermediate_state(h, message.len());
        let (sender, receiver) = ghash_to_finalized(sender, receiver);

        let message_short = Block::random_vec(&mut rng, 5);

        let (sender, receiver) = (
            sender.change_max_hashkey(message_short.len()),
            receiver.change_max_hashkey(message_short.len()),
        );

        let (sender, receiver) = ghash_to_finalized(sender, receiver);

        let output =
            sender.finalize(&message_short).unwrap() ^ receiver.finalize(&message_short).unwrap();

        assert_eq!(
            output,
            ghash_reference_impl(h.to_inner().reverse_bits(), &message_short)
        );
    }

    #[test]
    fn test_ghash_change_message_long() {
        let mut rng = ChaCha12Rng::from_seed([0; 32]);

        // The Ghash key.
        let h: Gf2_128 = rng.gen();
        let message = Block::random_vec(&mut rng, 10);

        let (sender, receiver) = setup_ghash_to_intermediate_state(h, message.len());
        let (sender, receiver) = ghash_to_finalized(sender, receiver);

        let message_long = Block::random_vec(&mut rng, 20);

        let (sender, receiver) = (
            sender.change_max_hashkey(message_long.len()),
            receiver.change_max_hashkey(message_long.len()),
        );

        let (sender, receiver) = ghash_to_finalized(sender, receiver);
        let output =
            sender.finalize(&message_long).unwrap() ^ receiver.finalize(&message_long).unwrap();

        assert_eq!(
            output,
            ghash_reference_impl(h.to_inner().reverse_bits(), &message_long)
        );
    }

    #[test]
    fn test_compute_missing_mul_shares() {
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let h: Gf2_128 = rng.gen();
        let mut powers: Vec<Gf2_128> = vec![h];
        compute_product_repeated(&mut powers, h * h, rng.gen_range(16..128));

        let powers_len = powers.len();
        let needed = rng.gen_range(1..256);

        compute_missing_mul_shares(&mut powers, needed);

        // Check length.
        if needed / 2 + (needed & 1) <= powers_len {
            assert_eq!(powers.len(), powers_len);
        } else {
            assert_eq!(powers.len(), needed / 2 + (needed & 1))
        }

        // Check shares.
        let first = *powers.first().unwrap();
        let factor = first * first;

        let mut expected = first;
        for share in powers.iter() {
            assert_eq!(*share, expected);
            expected = expected * factor;
        }
    }

    #[test]
    fn test_compute_new_add_shares() {
        let mut rng = ChaCha12Rng::from_seed([0; 32]);

        let new_add_odd_shares: Vec<Gf2_128> = gen_gf2_128_vec();
        let mut add_shares: Vec<Gf2_128> = gen_gf2_128_vec();

        // We have the invariant that len of add_shares is always even.
        if add_shares.len() & 1 == 1 {
            add_shares.push(rng.gen());
        }

        let original_len = add_shares.len();

        compute_new_add_shares(&new_add_odd_shares, &mut add_shares);

        // Check new length.
        assert_eq!(
            add_shares.len(),
            original_len + 2 * new_add_odd_shares.len()
        );

        // Check odd shares.
        for (k, l) in (original_len..add_shares.len())
            .step_by(2)
            .zip(0..original_len)
        {
            assert_eq!(add_shares[k], new_add_odd_shares[l]);
        }

        // Check even shares.
        for k in (original_len + 1..add_shares.len()).step_by(2) {
            assert_eq!(add_shares[k], add_shares[k / 2] * add_shares[k / 2]);
        }
    }

    fn gen_gf2_128_vec() -> Vec<Gf2_128> {
        let mut rng = ChaCha12Rng::from_seed([0; 32]);

        // Sample some message.
        let message_len: usize = rng.gen_range(16..128);
        let mut message: Vec<Gf2_128> = vec![Gf2_128::zero(); message_len];
        message.iter_mut().for_each(|x| *x = rng.gen());
        message
    }

    fn ghash_reference_impl(h: u128, message: &[Block]) -> Block {
        let mut ghash = GHash::new(&h.to_be_bytes().into());
        for el in message {
            let block = GenericArray::clone_from_slice(el.to_bytes().as_slice());
            ghash.update(&[block]);
        }
        let ghash_output = ghash.finalize();
        Block::from(ghash_output)
    }

    fn setup_ghash_to_intermediate_state(
        hashkey: Gf2_128,
        max_hashkey_power: usize,
    ) -> (GhashCore<Intermediate>, GhashCore<Intermediate>) {
        let mut rng = ChaCha12Rng::from_seed([0; 32]);

        // Create a multiplicative sharing.
        let h1_multiplicative: Gf2_128 = rng.gen();
        let h2_multiplicative: Gf2_128 = hashkey * h1_multiplicative.inverse();

        let sender = GhashCore::new(max_hashkey_power);
        let receiver = GhashCore::new(max_hashkey_power);

        let (sender, receiver) = (
            sender.compute_odd_mul_powers(h1_multiplicative),
            receiver.compute_odd_mul_powers(h2_multiplicative),
        );

        (sender, receiver)
    }

    fn ghash_to_finalized(
        sender: GhashCore<Intermediate>,
        receiver: GhashCore<Intermediate>,
    ) -> (GhashCore<Finalized>, GhashCore<Finalized>) {
        let (add_shares_sender, add_shares_receiver) =
            m2a(&sender.odd_mul_shares(), &receiver.odd_mul_shares());
        let (sender, receiver) = (
            sender.add_new_add_shares(&add_shares_sender),
            receiver.add_new_add_shares(&add_shares_receiver),
        );
        (sender, receiver)
    }

    fn m2a(first: &[Gf2_128], second: &[Gf2_128]) -> (Vec<Gf2_128>, Vec<Gf2_128>) {
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let mut first_out = vec![];
        let mut second_out = vec![];
        for (j, k) in first.iter().zip(second.iter()) {
            let product = *j * *k;
            let first_summand: Gf2_128 = rng.gen();
            let second_summand: Gf2_128 = product + first_summand;
            first_out.push(first_summand);
            second_out.push(second_summand);
        }
        (first_out, second_out)
    }
}
