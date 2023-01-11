use super::{
    compute_missing_mul_shares, compute_new_add_shares, mul,
    state::{Finalized, Init, Intermediate, State},
    GhashError,
};

/// The core logic for our 2PC Ghash implementation
///
/// `GhashCore` will do all the necessary computation
pub struct GhashCore<T: State = Init> {
    /// Inner state
    state: T,
    /// Maximum number of message blocks we want to authenticate
    max_message_length: usize,
}

impl GhashCore {
    /// Create a new `GhashCore`
    ///
    /// * `hashkey` - This is an additive sharing of `H`, which is the AES-encrypted 0 block
    /// * `max_message_length` - Determines the maximum number of 128-bit message blocks we want to
    ///                          authenticate
    pub fn new(hashkey: u128, max_message_length: usize) -> Result<Self, GhashError> {
        if max_message_length == 0 {
            return Err(GhashError::ZeroHashkeyPower);
        }

        Ok(Self {
            state: Init { add_share: hashkey },
            max_message_length,
        })
    }

    /// Returns the original hashkey
    ///
    /// This is an additive sharing of `H`
    pub fn h_additive(&self) -> u128 {
        self.state.add_share
    }

    /// Transform `self` into a `GhashCore<Intermediate>`, holding multiplicative shares of
    /// powers of `H`
    ///
    /// Converts `H` into `H`, `H^3`, `H^5`, ... depending on `self.max_message_length`
    pub fn compute_odd_mul_powers(self, mul_share: u128) -> GhashCore<Intermediate> {
        let mut hashkey_powers = vec![mul_share];

        compute_missing_mul_shares(&mut hashkey_powers, self.max_message_length);

        GhashCore {
            state: Intermediate {
                odd_mul_shares: hashkey_powers,
                cached_add_shares: vec![],
            },
            max_message_length: self.max_message_length,
        }
    }
}

impl GhashCore<Intermediate> {
    /// Return odd multiplicative shares of the hashkey
    ///
    /// Takes into account cached additive shares, so that
    /// multiplicative ones for which already an additive one
    /// exists, are not returned.
    pub fn odd_mul_shares(&self) -> Vec<u128> {
        // If we already have some cached additive sharings, we do not need to compute new powers.
        // So we compute an offset to ignore them. We divide by 2 because
        // `self.state.cached_add_shares` contain even and odd powers, while
        // `self.state.odd_mul_shares` only have odd powers.
        let offset = self.state.cached_add_shares.len() / 2;

        self.state.odd_mul_shares[offset..].to_vec()
    }

    /// Adds new additive shares of hashkey powers
    ///
    /// Adds new additive hashkey powers by also computing the even ones
    /// and transforms `self` into a `GhashCore<Finalized>`
    pub fn add_new_add_shares(mut self, new_additive_odd_shares: &[u128]) -> GhashCore<Finalized> {
        compute_new_add_shares(new_additive_odd_shares, &mut self.state.cached_add_shares);

        GhashCore {
            state: Finalized {
                add_shares: self.state.cached_add_shares,
                odd_mul_shares: self.state.odd_mul_shares,
            },
            max_message_length: self.max_message_length,
        }
    }
}

impl GhashCore<Finalized> {
    /// Generate the GHASH output
    ///
    /// Computes the 2PC additive share of the GHASH output
    pub fn ghash_output(&self, message: &[u128]) -> Result<u128, GhashError> {
        if message.len() > self.max_message_length {
            return Err(GhashError::InvalidMessageLength);
        }
        let offset = self.state.add_shares.len() - message.len();
        Ok(message
            .iter()
            .zip(self.state.add_shares.iter().rev().skip(offset))
            .fold(0, |acc, (block, share)| acc ^ mul(*block, *share)))
    }

    /// Change the maximum hashkey power
    ///
    /// If we want to create a GHASH output for a new message, which is longer than the old one, we need
    /// to compute the missing powers of `H`.
    pub fn change_max_hashkey(self, new_highest_hashkey_power: usize) -> GhashCore<Intermediate> {
        let mut hashkey_powers = self.state.odd_mul_shares;
        compute_missing_mul_shares(&mut hashkey_powers, new_highest_hashkey_power);

        GhashCore {
            state: Intermediate {
                odd_mul_shares: hashkey_powers,
                cached_add_shares: self.state.add_shares,
            },
            max_message_length: new_highest_hashkey_power,
        }
    }
}

#[cfg(test)]
impl<T: State> GhashCore<T> {
    pub fn state(&self) -> &T {
        &self.state
    }
}
