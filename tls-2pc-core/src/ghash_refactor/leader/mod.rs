//! Implements the GHASH Master. This is the party which holds the Y value of
//! block multiplication. Master acts as the receiver of the Oblivious
//! Transfer and receives Slaves's masked X table entries obliviously for each
//! bit of Y.
pub mod state;

use super::utils::{
    block_aggregation, block_aggregation_bits, block_mult, flat_to_chunks,
    multiply_powers_and_blocks, square_all, xor_sum,
};
use super::{GhashCommon, GhashError, YBits};
use state::{Initialized, Post, Receive, Received, Round1, Round2, Round3, Round4, Sent};

pub struct GHashLeader<T = Initialized<Sent>> {
    state: T,
    // is_last_round will be set to true by next_request() to indicate that
    // after the response is received the state must be set to Complete
    is_last_round: bool,
}

impl GHashLeader {
    pub fn new(ghash_key_share: u128, blocks: Vec<u128>) -> Result<Self, GhashError> {
        let common = GhashCommon::new(ghash_key_share, blocks)?;
        Ok(Self {
            state: Initialized {
                common,
                marker: std::marker::PhantomData,
            },
            is_last_round: false,
        })
    }
}

impl GHashLeader<Initialized<Sent>> {
    pub fn next_request(mut self) -> (GHashLeader<Round1<Sent>>, YBits) {
        let y_bits = self.next();
        (
            GHashLeader {
                state: Round1 {
                    common: self.state.common,
                    marker: std::marker::PhantomData,
                },
                is_last_round: self.is_last_round,
            },
            y_bits,
        )
    }
}

impl<T: Receive> GHashLeader<T> {
    fn next(&mut self) -> YBits {
        if self.state.is_next_round_needed() {
            self.is_last_round = false;
            self.state.y_bits_for_next_round().concat()
        } else {
            self.is_last_round = true;
            self.state.ybits_for_block_aggr().concat()
        }
    }
}

impl<T: Post> GHashLeader<T> {
    fn process(&mut self, response: &Vec<u128>) -> Result<(), GhashError> {
        if response.len() % 128 != 0 {
            return Err(GhashError::DataLengthWrong);
        }
        let mxtables = flat_to_chunks(response, 128);
        self.state.process_mxtables(&mxtables);

        if self.is_last_round {
            self.state.compute_ghash();
        }
        Ok(())
    }
}
