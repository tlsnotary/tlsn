pub mod state;
use super::utils::{block_aggregation, block_aggregation_bits, multiply_powers_and_blocks};
use super::{GhashCommon, GhashError, YBits};
use state::{Initialized, State};

pub struct GHashLeader<T = Initialized>(T)
where
    T: State;

impl GHashLeader {
    pub fn new(ghash_key_share: u128, blocks: Vec<u128>) -> Result<Self, GhashError> {
        let common = GhashCommon::new(ghash_key_share, blocks)?;
        Ok(Self(Initialized { common }))
    }
}

impl<T: State> GHashLeader<T> {
    pub fn is_next_round_needed(&self) -> bool {
        self.0.is_next_round_needed()
    }
}
