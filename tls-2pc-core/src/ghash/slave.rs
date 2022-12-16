//! Implements the GHASH Slave. This is the party which holds the X value of
//! block multiplication. Slave acts as the sender of the Oblivious
//! Transfer and sends masked x_table entries obliviously for each
//! bit of Y received from the GHASH Master.

use super::{
    common::GhashCommon,
    errors::*,
    utils::{
        block_aggregation, block_aggregation_mxtables, block_mult, free_square, masked_xtable,
        multiply_powers_and_blocks, square_all,
    },
    MXTableFull, SlaveCore,
};
use rand::{CryptoRng, Rng};
use std::collections::BTreeMap;

#[derive(PartialEq)]
pub enum SlaveState {
    Initialized,
    // There may be from 1 to 4 rounds depending on GHASH block count
    RoundReceived(usize),
    Complete,
}

pub struct GhashSlave<R> {
    c: GhashCommon,
    rng: R,
    state: SlaveState,
}

impl<R: Rng + CryptoRng> SlaveCore for GhashSlave<R> {
    fn process_request(&mut self) -> Result<Vec<[u128; 2]>, GhashError> {
        let retval;
        let is_complete;
        match self.state {
            SlaveState::Initialized => {
                self.state = SlaveState::RoundReceived(1);
                retval = self.get_mxtables_for_round1().concat();
                is_complete = self.is_only_1_round();
            }
            SlaveState::RoundReceived(1) => {
                if self.is_round2_needed() {
                    self.state = SlaveState::RoundReceived(2);
                    retval = self.get_mxtables_for_round(2).concat();
                    is_complete = false;
                } else {
                    // rounds 2 and 3 will be skipped
                    self.state = SlaveState::RoundReceived(4);
                    retval = self.get_mxtables_for_block_aggr().concat();
                    is_complete = true;
                }
            }
            SlaveState::RoundReceived(2) => {
                if self.is_round3_needed() {
                    self.state = SlaveState::RoundReceived(3);
                    retval = self.get_mxtables_for_round(3).concat();
                    is_complete = false;
                } else {
                    // round 3 will be skipped
                    self.state = SlaveState::RoundReceived(4);
                    retval = self.get_mxtables_for_block_aggr().concat();
                    is_complete = true;
                }
            }
            SlaveState::RoundReceived(3) => {
                self.state = SlaveState::RoundReceived(4);
                retval = self.get_mxtables_for_block_aggr().concat();
                is_complete = true;
            }
            _ => {
                return Err(GhashError::OutOfOrder);
            }
        }
        if is_complete {
            if self.state != SlaveState::RoundReceived(4) {
                // if the last round was not round 4 (i.e. there was no block
                // aggregation), then we compute GHASH directly
                self.c.temp_share =
                    Some(multiply_powers_and_blocks(&self.c.powers, &self.c.blocks));
            }
            self.state = SlaveState::Complete;
        }
        Ok(retval)
    }

    fn finalize(&mut self) -> Result<u128, GhashError> {
        if self.state != SlaveState::Complete {
            return Err(GhashError::FinalizeCalledTooEarly);
        }
        Ok(self.c.temp_share.unwrap())
    }

    fn is_complete(&mut self) -> bool {
        self.state == SlaveState::Complete
    }

    fn export_powers(&mut self) -> BTreeMap<u16, u128> {
        self.c.export_powers()
    }

    fn calculate_ot_count(&mut self) -> usize {
        self.c.calculate_ot_count()
    }
}

impl<R: Rng + CryptoRng> GhashSlave<R> {
    pub fn new(rng: R, ghash_key_share: u128, blocks: Vec<u128>) -> Result<Self, GhashError> {
        let c = GhashCommon::new(ghash_key_share, blocks)?;
        Ok(Self {
            c,
            rng,
            state: SlaveState::Initialized,
        })
    }

    fn is_round2_needed(&self) -> bool {
        self.c.is_round2_needed()
    }

    fn is_round3_needed(&self) -> bool {
        self.c.is_round3_needed()
    }

    fn is_only_1_round(&self) -> bool {
        self.c.is_only_1_round()
    }

    /// Returns the masked X table for round 1.
    /// Since the Master (M) sends bits for his powers in ascending order, we need to
    /// accomodate that order, i.e. if we need to multiply M's H^1 by
    /// our H^2 and then multiply M's H^2 by our H^1, then we return [mxtable
    /// for H^2 + mxtable for H^1].
    fn get_mxtables_for_round1(&mut self) -> Vec<MXTableFull> {
        self.c.powers.insert(2, free_square(self.c.powers[&1]));
        let (masked1, h3_share1) = masked_xtable(&mut self.rng, self.c.powers[&1]);
        let (masked2, h3_share2) = masked_xtable(&mut self.rng, self.c.powers[&2]);

        self.c.powers.insert(
            3,
            block_mult(self.c.powers[&1], self.c.powers[&2]) ^ h3_share1 ^ h3_share2,
        );
        // since we just added a new share of powers, we need to square them
        self.c.powers = square_all(&self.c.powers, self.c.blocks.len() as u16);
        vec![masked2, masked1]
    }

    /// Returns masked X tables for either round 2 or round 3.
    fn get_mxtables_for_round(&mut self, round_no: u8) -> Vec<MXTableFull> {
        assert!(round_no == 2 || round_no == 3);
        let mut all_mxtables: Vec<MXTableFull> = Vec::new();
        for (key, value) in self.c.strategies[(round_no - 2) as usize].clone().iter() {
            if *key > self.c.max_odd_power {
                break;
            }
            // Since Master sends bits in ascending order: factor1 bits,
            // factor2 bits, we must return mxtables in descending order:
            // factor2 mxtable, factor1 mxtable.
            let factor1 = self.c.powers[&(value[0] as u16)];
            let factor2 = self.c.powers[&(value[1] as u16)];
            let (mxtable1, sum1) = masked_xtable(&mut self.rng, factor1);
            let (mxtable2, sum2) = masked_xtable(&mut self.rng, factor2);
            all_mxtables.push(mxtable2);
            all_mxtables.push(mxtable1);

            // our share of power <key> is the locally computed term plus sums
            // of masks of each cross-term.
            let local_term = block_mult(factor1, factor2);
            self.c.powers.insert(*key as u16, local_term ^ sum1 ^ sum2);
        }
        // since we just added a few new shares of powers, we need to square them
        self.c.powers = square_all(&self.c.powers, self.c.blocks.len() as u16);
        all_mxtables
    }

    /// Returns masked X tables for the block aggregation method.
    fn get_mxtables_for_block_aggr(&mut self) -> Vec<MXTableFull> {
        let share1 = multiply_powers_and_blocks(&self.c.powers, &self.c.blocks);
        let (aggregated, share2) = block_aggregation(&self.c.powers, &self.c.blocks);
        let (mxtables, share3) =
            block_aggregation_mxtables(&mut self.rng, &self.c.powers, &aggregated);
        self.c.temp_share = Some(share1 ^ share2 ^ share3);
        mxtables
    }
}
