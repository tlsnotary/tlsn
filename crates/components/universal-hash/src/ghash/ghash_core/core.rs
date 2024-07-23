use mpz_core::Block;
use mpz_fields::{gf2_128::Gf2_128, Field};
use tracing::instrument;

use super::{
    compute_missing_mul_shares, compute_new_add_shares,
    state::{Finalized, Init, Intermediate, State},
    GhashError,
};

/// The core logic for the 2PC Ghash implementation.
///
/// `GhashCore` will do all the necessary computation.
#[derive(Debug)]
pub(crate) struct GhashCore<T: State = Init> {
    /// Inner state.
    state: T,
    /// Maximum number of message blocks we want to authenticate.
    max_block_count: usize,
}

impl GhashCore {
    /// Creates a new `GhashCore`.
    ///
    /// # Arguments
    ///
    /// * `max_block_count` - Determines the maximum number of 128-bit message blocks we want to
    ///                       authenticate. Panics if `max_block_count` is 0.
    pub(crate) fn new(max_block_count: usize) -> Self {
        assert!(max_block_count > 0);

        Self {
            state: Init,
            max_block_count,
        }
    }

    /// Transforms `self` into a `GhashCore<Intermediate>`, holding multiplicative shares of
    /// powers of `H`.
    ///
    /// Converts `H` into `H`, `H^3`, `H^5`, ... depending on `self.max_block_count`.
    #[instrument(level = "trace", skip_all)]
    pub(crate) fn compute_odd_mul_powers(self, mul_share: Gf2_128) -> GhashCore<Intermediate> {
        let mut hashkey_powers = vec![mul_share];

        compute_missing_mul_shares(&mut hashkey_powers, self.max_block_count);

        GhashCore {
            state: Intermediate {
                odd_mul_shares: hashkey_powers,
                cached_add_shares: vec![],
            },
            max_block_count: self.max_block_count,
        }
    }
}

impl GhashCore<Intermediate> {
    /// Returns odd multiplicative shares of the hashkey.
    ///
    /// Takes into account cached additive shares, so that
    /// multiplicative ones for which already an additive one
    /// exists, are not returned.
    #[instrument(level = "trace", skip_all)]
    pub(crate) fn odd_mul_shares(&self) -> Vec<Gf2_128> {
        // If we already have some cached additive sharings, we do not need to compute new powers.
        // So we compute an offset to ignore them. We divide by 2 because
        // `self.state.cached_add_shares` contain even and odd powers, while
        // `self.state.odd_mul_shares` only have odd powers.
        let offset = self.state.cached_add_shares.len() / 2;

        self.state.odd_mul_shares[offset..].to_vec()
    }

    /// Adds new additive shares of hashkey powers by also computing the even ones
    /// and transforms `self` into a `GhashCore<Finalized>`.
    #[instrument(level = "trace", skip_all)]
    pub(crate) fn add_new_add_shares(
        mut self,
        new_additive_odd_shares: &[Gf2_128],
    ) -> GhashCore<Finalized> {
        compute_new_add_shares(new_additive_odd_shares, &mut self.state.cached_add_shares);

        GhashCore {
            state: Finalized {
                add_shares: self.state.cached_add_shares,
                odd_mul_shares: self.state.odd_mul_shares,
            },
            max_block_count: self.max_block_count,
        }
    }
}

impl GhashCore<Finalized> {
    /// Returns the currently configured maximum message length.
    pub(crate) fn get_max_blocks(&self) -> usize {
        self.max_block_count
    }

    /// Generates the GHASH output.
    ///
    /// Computes the 2PC additive share of the GHASH output.
    #[instrument(level = "debug", skip_all, err)]
    pub(crate) fn finalize(&self, message: &[Block]) -> Result<Block, GhashError> {
        if message.len() > self.max_block_count {
            return Err(GhashError::InvalidMessageLength);
        }
        let offset = self.state.add_shares.len() - message.len();

        let output: Block = message
            .iter()
            .zip(self.state.add_shares.iter().rev().skip(offset))
            .fold(Gf2_128::zero(), |acc, (block, share)| {
                acc + Gf2_128::from(block.reverse_bits()) * *share
            })
            .into();

        Ok(output.reverse_bits())
    }

    /// Changes the maximum hashkey power.
    ///
    /// If we want to create a GHASH output for a new message, which is longer than the old one, we need
    /// to compute the missing shares of the powers of `H`.
    #[instrument(level = "debug", skip(self))]
    pub(crate) fn change_max_hashkey(
        self,
        new_highest_hashkey_power: usize,
    ) -> GhashCore<Intermediate> {
        let mut present_odd_mul_shares = self.state.odd_mul_shares;
        compute_missing_mul_shares(&mut present_odd_mul_shares, new_highest_hashkey_power);

        GhashCore {
            state: Intermediate {
                odd_mul_shares: present_odd_mul_shares,
                cached_add_shares: self.state.add_shares,
            },
            max_block_count: new_highest_hashkey_power,
        }
    }
}

#[cfg(test)]
impl<T: State> GhashCore<T> {
    pub(crate) fn state(&self) -> &T {
        &self.state
    }
}
