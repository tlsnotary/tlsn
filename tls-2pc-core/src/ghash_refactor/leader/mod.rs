pub mod state;

use super::utils::{block_aggregation, block_aggregation_bits, multiply_powers_and_blocks};
use super::{GhashCommon, GhashError, YBits};
use state::{Initialized, Round1, Round2, Round3, Received};

pub struct GHashLeader<T = Initialized>(T)
where
    T: Received;

impl GHashLeader {
    pub fn new(ghash_key_share: u128, blocks: Vec<u128>) -> Result<Self, GhashError> {
        let common = GhashCommon::new(ghash_key_share, blocks)?;
        Ok(Self(Initialized { common }))
    }
}

impl<T: Received> GHashLeader<T> {
    pub fn next_request(self) -> GHashLeaderWrapper {
        let next_round = self.0.is_next_round_needed();
        match <T as Received>::ROUND {
            0 => self.0 =

        }
    }
}

enum GHashLeaderWrapper {
    Init(GHashLeader<Initialized>),
    Round1(GHashLeader<Round1>),
    Round2(GHashLeader<Round2>),
    Round3(GHashLeader<Round3>),
}
