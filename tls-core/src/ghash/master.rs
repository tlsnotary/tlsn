//! Implements the GHASH Master. This is the party which holds the Y value of
//! block multiplication. Master acts as the receiver of the Oblivious
//! Transfer and receives Slaves's masked X table entries obliviously for each
//! bit of Y.
use super::utils::{
    block_aggregation, block_aggregation_bits, block_mult, flat_to_chunks,
    multiply_powers_and_blocks, square_all, xor_sum,
};
use super::{errors::*, MasterCore};
use crate::ghash::common::GhashCommon;
use crate::ghash::{MXTable, YBits};
use mpc_core::utils::u8vec_to_boolvec;
use std::collections::BTreeMap;

#[derive(PartialEq)]
pub enum MasterState {
    Initialized,
    // There may be 1, 2, 3 or 4 rounds depending on GHASH block count
    RoundSent(usize),
    RoundReceived(usize),
    Complete,
}

pub struct GhashMaster {
    c: GhashCommon,
    state: MasterState,
    // is_last_round will be set to true by next_request() to indicate that
    // after the response is received the state must be set to Complete
    is_last_round: bool,
}

impl MasterCore for GhashMaster {
    fn next_request(&mut self) -> Result<Vec<bool>, GhashError> {
        let retval;
        let is_complete;
        match self.state {
            MasterState::Initialized => {
                self.state = MasterState::RoundSent(1);
                retval = self.get_ybits_for_round1().concat();
                is_complete = self.is_only_1_round();
            }
            MasterState::RoundReceived(1) => {
                if self.is_round2_needed() {
                    self.state = MasterState::RoundSent(2);
                    retval = self.get_ybits_for_round(2).concat();
                    is_complete = false;
                } else {
                    // rounds 2 and 3 will be skipped
                    self.state = MasterState::RoundSent(4);
                    retval = self.get_ybits_for_block_aggr().concat();
                    is_complete = true;
                }
            }
            MasterState::RoundReceived(2) => {
                if self.is_round3_needed() {
                    self.state = MasterState::RoundSent(3);
                    retval = self.get_ybits_for_round(3).concat();
                    is_complete = false;
                } else {
                    // round 3 will be skipped
                    self.state = MasterState::RoundSent(4);
                    retval = self.get_ybits_for_block_aggr().concat();
                    is_complete = true;
                }
            }
            MasterState::RoundReceived(3) => {
                self.state = MasterState::RoundSent(4);
                retval = self.get_ybits_for_block_aggr().concat();
                is_complete = true;
            }
            _ => {
                return Err(GhashError::OutOfOrder);
            }
        }
        if is_complete {
            self.is_last_round = true;
        }
        Ok(retval)
    }

    fn process_response(&mut self, response: &Vec<u128>) -> Result<(), GhashError> {
        if response.len() % 128 != 0 {
            return Err(GhashError::DataLengthWrong);
        }
        let mxtables = flat_to_chunks(response, 128);
        match self.state {
            MasterState::RoundSent(1) => {
                self.state = MasterState::RoundReceived(1);
                self.process_mxtables_for_round1(&mxtables);
            }
            MasterState::RoundSent(2) => {
                self.state = MasterState::RoundReceived(2);
                self.process_mxtables_for_round(&mxtables, 2);
            }
            MasterState::RoundSent(3) => {
                self.state = MasterState::RoundReceived(3);
                self.process_mxtables_for_round(&mxtables, 3);
            }
            MasterState::RoundSent(4) => {
                self.state = MasterState::RoundReceived(4);
                self.process_mxtables_for_block_aggr(&mxtables);
            }
            _ => {
                return Err(GhashError::OutOfOrder);
            }
        }
        if self.is_last_round {
            if self.state != MasterState::RoundReceived(4) {
                // if the last round was not round 4 (i.e. there was no block
                // aggregation), then we compute GHASH directly
                self.c.temp_share =
                    Some(multiply_powers_and_blocks(&self.c.powers, &self.c.blocks));
            }
            self.state = MasterState::Complete;
        }
        Ok(())
    }

    fn is_complete(&mut self) -> bool {
        self.state == MasterState::Complete
    }

    fn finalize(&mut self) -> Result<u128, GhashError> {
        if self.state != MasterState::Complete {
            return Err(GhashError::FinalizeCalledTooEarly);
        }
        Ok(self.c.temp_share.unwrap())
    }

    /// Returns the amount of Oblivious Transfer instances needed to complete
    /// the protocol. The purpose is to inform the OT layer.
    fn calculate_ot_count(&mut self) -> usize {
        self.c.calculate_ot_count()
    }

    fn export_powers(&mut self) -> BTreeMap<u16, u128> {
        self.c.export_powers()
    }
}

impl GhashMaster {
    pub fn new(ghash_key_share: u128, blocks: Vec<u128>) -> Result<Self, GhashError> {
        let common = GhashCommon::new(ghash_key_share, blocks)?;
        Ok(Self {
            c: common,
            state: MasterState::Initialized,
            is_last_round: false,
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

    /// Returns Y bits to compute H^3.
    fn get_ybits_for_round1(&mut self) -> Vec<YBits> {
        vec![
            u8vec_to_boolvec(&self.c.powers[&1].to_be_bytes()),
            u8vec_to_boolvec(&self.c.powers[&2].to_be_bytes()),
        ]
    }

    /// Takes masked X tables and computes our share of H^3.
    fn process_mxtables_for_round1(&mut self, mxtables: &Vec<MXTable>) {
        // the XOR sum of all masked xtables' values plus H^1*H^2 is our share of H^3
        self.c.powers.insert(
            3,
            xor_sum(&mxtables[0])
                ^ xor_sum(&mxtables[1])
                ^ block_mult(self.c.powers[&1], self.c.powers[&2]),
        );
        // since we just added a new share of powers, we need to square them
        self.c.powers = square_all(&self.c.powers, self.c.blocks.len() as u16);
    }

    // Returns Y bits for a given round of communication.
    fn get_ybits_for_round(&mut self, round_no: u8) -> Vec<YBits> {
        assert!(round_no == 2 || round_no == 3);
        let mut bits: Vec<YBits> = Vec::new();
        for (key, value) in self.c.strategies[(round_no - 2) as usize].iter() {
            if *key > self.c.max_odd_power {
                break;
            }
            bits.push(u8vec_to_boolvec(
                &self.c.powers[&(value[0] as u16)].to_be_bytes(),
            ));
            bits.push(u8vec_to_boolvec(
                &self.c.powers[&(value[1] as u16)].to_be_bytes(),
            ));
        }
        bits
    }

    /// Processes masked X tables for a given round of communication.
    fn process_mxtables_for_round(&mut self, mxtables: &Vec<MXTable>, round_no: u8) {
        assert!(round_no == 2 || round_no == 3);
        for (count, (power, factors)) in self.c.strategies[(round_no - 2) as usize]
            .iter()
            .enumerate()
        {
            if *power > self.c.max_odd_power {
                // for every key in the strategy which we processed, there
                // must have been 2 masked xtables
                assert!(count * 2 == mxtables.len());
                break;
            }
            // the XOR sum of 2 masked xtables' values plus the locally computed
            // term is our share of power
            let sum = xor_sum(&mxtables[count * 2]) ^ xor_sum(&mxtables[(count * 2) + 1]);
            let local_term = block_mult(
                self.c.powers[&(factors[0] as u16)],
                self.c.powers[&(factors[1] as u16)],
            );
            self.c.powers.insert(*power as u16, sum ^ local_term);
        }
        // since we just added a few new shares of powers, we need to square them
        self.c.powers = square_all(&self.c.powers, self.c.blocks.len() as u16);
    }

    /// Returns Y bits for the block aggregation method.
    fn get_ybits_for_block_aggr(&mut self) -> Vec<YBits> {
        let share1 = multiply_powers_and_blocks(&self.c.powers, &self.c.blocks);
        let (aggregated, share2) = block_aggregation(&self.c.powers, &self.c.blocks);
        let choice_bits = block_aggregation_bits(&self.c.powers, &aggregated);
        self.c.temp_share = Some(share1 ^ share2);
        choice_bits
    }

    /// Processes masked X tables for the block aggregation method.
    fn process_mxtables_for_block_aggr(&mut self, mxtables: &Vec<MXTable>) {
        let mut share = 0u128;
        for table in mxtables.iter() {
            share ^= xor_sum(table);
        }
        self.c.temp_share = Some(self.c.temp_share.unwrap() ^ share);
    }
}
