//! This module implements the AES-GCM's GHASH function in a
//! secure two-party computation (2PC) setting using 1-out-of-2 Oblivious
//! Transfer (OT). The parties start with their secret XOR shares of H (the
//! GHASH key) and at the end each gets their XOR share of the GHASH output.
//! The method is decribed here <https://tlsnotary.org/how_it_works#section4>.

//! As an illustration, let's say that S has his shares H1_s and H2_s and R
//! has her shares H1_r and H2_r. They need to compute shares of H3.
//! H3 = (H1_s + H1_r)*(H2_s + H2_r) = H1_s*H2_s + H1_s*H2_r + H1_r*H2_s +
//! H1_r*H2_r. Term 1 can be computed by S locally and term 4 can be
//! computed by R locally. Only terms 2 and 3 will be computed using
//! GHASH 2PC. R will obliviously request values for bits of H1_r and H2_r.
//! The XOR sum of all values which S will send back plus H1_r*H2_r will
//! become R's share of H3.

use gf2_128::mul;

/// Ghash struct
///
/// Contains the core logic needed for Ghash
pub struct Ghash {
    /// The ciphertext for which we want to generate a MAC
    ciphertext: Vec<u128>,
    /// Shares of H^n
    hashkey_power_shares: Vec<u128>,
    /// powers of the share H
    powers_h: Vec<u128>,
    /// the maximum power of H needed to build H^n
    max_needed_power: u32,
}

impl Ghash {
    /// Creates a new instance
    ///
    /// * `hashkey` - the 0 block encrypted with the AES-GCM keyshare
    /// * `ciphertext` - the ciphertext, for which a MAC should be created
    pub fn new(hashkey: u128, ciphertext: Vec<u128>) -> Self {
        let max_needed_power = max_needed_power(ciphertext.len() as u32);

        let mut hashkey_power_shares = vec![0_u128; ciphertext.len() + 1];
        hashkey_power_shares[0] = 1;
        hashkey_power_shares[1] = hashkey;
        Self {
            ciphertext,
            hashkey_power_shares,
            powers_h: h_to_n(hashkey, max_needed_power),
            max_needed_power,
        }
    }

    /// Add a new hashkey power share
    ///
    /// This function allows to add a hashkey share of power `power`.
    pub fn add_share(
        &mut self,
        power: usize,
        composite_first: Option<u128>,
        composite_second: Option<u128>,
    ) -> Result<(), GhashError> {
        if power > self.ciphertext.len() {
            return Err(GhashError::ShareNotNeeded);
        }

        if power.is_power_of_two() {
            self.hashkey_power_shares[power] = self.powers_h[power];
            return Ok(());
        }

        let first_power = power / 2;
        let second_power = first_power + power & 1;
        let mut hashkey_power_share = mul(
            *self
                .hashkey_power_shares
                .get(first_power)
                .ok_or(GhashError::MissingHashkeyShare)?,
            *self
                .hashkey_power_shares
                .get(second_power)
                .ok_or(GhashError::MissingHashkeyShare)?,
        );
        if power & 1 == 1 {
            hashkey_power_share ^= composite_first.ok_or(GhashError::MissingCompositeShare)?
                ^ composite_second.ok_or(GhashError::MissingCompositeShare)?;
        }
        self.hashkey_power_shares[power] = hashkey_power_share;
        Ok(())
    }

    /// Determines the powers needed for the OT exchange
    ///
    /// Determine which additive shares of composite terms `H_1^l * H_2^k`
    /// are needed for all powers up to and including `H^n`
    fn determine_composites(&self) -> Vec<(u32, u32)> {
        let mut composite_terms: Vec<(u32, u32)> = vec![];

        for k in 1..self.max_needed_power {
            composite_terms.push((k, k + 1))
        }
        composite_terms
    }

    /// Returns the final MAC
    ///
    /// When all the needed shares are collected, calculate the MAC
    pub fn finalize(&self) -> Result<u128, GhashError> {
        if self.ciphertext.len() != self.hashkey_power_shares.len() {
            return Err(GhashError::MissingHashkeyShare);
        }
        let mut mac = 0_u128;
        for (cipherblock, h) in self.ciphertext.iter().zip(self.hashkey_power_shares.iter()) {
            mac ^= mul(*cipherblock, *h);
        }
        Ok(mac)
    }
}

/// Computes powers of the hashkey share
///
/// Computes all needed powers of H_1 needed to build H^n
fn h_to_n(h: u128, n: u32) -> Vec<u128> {
    let mut powers_h = vec![1, h];

    for _ in 0..max_needed_power(n) + 1 {
        let next = mul(*powers_h.last().unwrap(), h);
        powers_h.push(next);
    }
    powers_h
}

/// Computes the maximum power `m` needed to build H^n
///
/// For example to compute H^11 we only need H^6
fn max_needed_power(n: u32) -> u32 {
    let mut needed_max_share = n >> 1;
    if n & 1 == 1 {
        needed_max_share += 1;
    }
    needed_max_share
}

/// Errors that may occur when using ghash module
#[derive(Debug, thiserror::Error)]
pub enum GhashError {
    #[error("Some shares are still missing")]
    MissingHashkeyShare,
    #[error("Some composite terms are missing")]
    MissingCompositeShare,
    #[error("A share of this power is not needed")]
    ShareNotNeeded,
}
