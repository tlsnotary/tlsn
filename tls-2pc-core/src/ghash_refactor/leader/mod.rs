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
use state::{
    Finalized, Initialized, Post, Receive, Received, Round1, Round2, Round3, Round4, Sent,
};

pub struct GHashLeader<T = Initialized<Received>> {
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

pub trait NextRequest {
    fn next_request(self) -> Result<(YBits, Box<dyn ProcessRequest>), GhashError>;
}

macro_rules! impl_next_request {
    ($for: ty, $to: tt) => {
        impl NextRequest for $for {
            fn next_request(mut self) -> Result<(Vec<bool>, Box<dyn ProcessRequest>), GhashError> {
                Ok(if self.state.is_next_round_needed() {
                    (
                        self.state.y_bits_for_next_round().concat(),
                        Box::new(GHashLeader {
                            state: $to {
                                common: self.state.common,
                                marker: std::marker::PhantomData::<Sent>,
                            },
                            is_last_round: false,
                        }),
                    )
                } else {
                    (
                        self.state.ybits_for_block_aggr().concat(),
                        Box::new(GHashLeader {
                            state: Round4 {
                                common: self.state.common,
                                marker: std::marker::PhantomData::<Sent>,
                            },
                            is_last_round: true,
                        }),
                    )
                })
            }
        }
    };
}

impl_next_request!(GHashLeader<Initialized<Received>>, Round1);
impl_next_request!(GHashLeader<Round1<Received>>, Round2);
impl_next_request!(GHashLeader<Round2<Received>>, Round3);
impl_next_request!(GHashLeader<Round3<Received>>, Round4);

impl NextRequest for GHashLeader<Finalized> {
    fn next_request(self) -> Result<(YBits, Box<dyn ProcessRequest>), GhashError> {
        Err(GhashError::FinalState)
    }
}

pub trait ProcessRequest {
    fn process_request(self, response: &Vec<u128>) -> Result<Box<dyn NextRequest>, GhashError>;
}

macro_rules! impl_process_request {
    ($for: ty, $to: tt) => {
        impl ProcessRequest for $for {
            fn process_request(
                mut self,
                response: &Vec<u128>,
            ) -> Result<Box<dyn NextRequest>, GhashError> {
                if response.len() % 128 != 0 {
                    return Err(GhashError::DataLengthWrong);
                }
                let mxtables = flat_to_chunks(response, 128);
                self.state.process_mxtables(&mxtables);

                if self.is_last_round {
                    self.state.compute_ghash();
                }

                Ok(Box::new(GHashLeader {
                    state: $to {
                        common: self.state.common,
                        marker: std::marker::PhantomData::<Received>,
                    },
                    is_last_round: self.is_last_round,
                }))
            }
        }
    };
}

impl_process_request!(GHashLeader<Round1<Sent>>, Round1);
impl_process_request!(GHashLeader<Round2<Sent>>, Round2);
impl_process_request!(GHashLeader<Round3<Sent>>, Round3);

impl ProcessRequest for GHashLeader<Round4<Sent>> {
    fn process_request(mut self, response: &Vec<u128>) -> Result<Box<dyn NextRequest>, GhashError> {
        if response.len() % 128 != 0 {
            return Err(GhashError::DataLengthWrong);
        }
        let mxtables = flat_to_chunks(response, 128);
        self.state.process_mxtables(&mxtables);

        if self.is_last_round {
            self.state.compute_ghash();
        }

        Ok(Box::new(GHashLeader {
            state: Finalized {
                common: self.state.common,
            },
            is_last_round: self.is_last_round,
        }))
    }
}

pub trait Status {
    fn is_complete(&self) -> bool {
        false
    }

    fn finalize(&self) -> Result<u128, GhashError> {
        Err(GhashError::FinalizeCalledTooEarly)
    }
}

impl<T: Receive> Status for GHashLeader<T> {}
impl Status for GHashLeader<Initialized<Received>> {}
impl Status for GHashLeader<Round1<Received>> {}
impl Status for GHashLeader<Round2<Received>> {}
impl Status for GHashLeader<Round3<Received>> {}
impl Status for GHashLeader<Finalized> {
    fn is_complete(&self) -> bool {
        true
    }

    fn finalize(&self) -> Result<u128, GhashError> {
        self.state.common.temp_share.ok_or(GhashError::NoFinalShare)
    }
}
