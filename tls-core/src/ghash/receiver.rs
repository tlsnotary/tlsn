// implements the GHASH receiver. This is the party which holds the Y value of
// block multiplication. The receiver acts as the receiver of the Oblivious
// Transfer and receives sender's masked x_table entries obliviously for each
// bit of Y.
use super::errors::*;
use super::utils::{
    block_aggregation, block_aggregation_bits, block_mult, find_max_odd_power,
    multiply_powers_and_blocks, square_all, xor_sum,
};
use crate::ghash::common::GhashCommon;
use crate::ghash::{MXTable, YBits};
use mpc_core::utils::u8vec_to_boolvec;
use std::collections::BTreeMap;

#[derive(PartialEq)]
pub enum ReceiverState {
    Initialized,
    // FinishedSent is sent after we send Client/Server Finished
    FinishedSent,
    FinishedReceived,
    // There may be 1 or 2 rounds depending on GHASH block count
    Round1Sent,
    Round1Received,
    Round2Sent,
    Round2Received,
    BlockAggregationSent,
    BlockAggregationReceived,
}

pub struct GhashReceiver {
    c: GhashCommon,
    // temp_share is used to save an intermediare GHASH share
    temp_share: u128,
    state: ReceiverState,
}

impl GhashReceiver {
    pub fn new(ghash_key_share: u128, blocks: Vec<u128>) -> Self {
        let common = GhashCommon::new(ghash_key_share, blocks);
        Self {
            c: common,
            temp_share: 0u128,
            state: ReceiverState::Initialized,
        }
    }

    // get_request_for_finished returns choice bits from which the caller
    // can build an OT request to compute GHASH for the Client/Server_Finished.
    pub fn get_request_for_finished(&mut self) -> Result<Vec<bool>, GhashError> {
        if self.state != ReceiverState::Initialized {
            return Err(GhashError::OutOfORder);
        }
        self.state = ReceiverState::FinishedSent;
        Ok(self.get_ybits_for_finished().concat())
    }

    // process_response_for_finished accept masked x tables received via OT
    // and returns our GHASH share for Client/Server_finished
    pub fn process_response_for_finished(
        &mut self,
        response: &Vec<u128>,
    ) -> Result<u128, GhashError> {
        if self.state != ReceiverState::FinishedSent {
            return Err(GhashError::OutOfORder);
        }
        self.state = ReceiverState::FinishedReceived;
        let mxtable = self.flat_to_mxtables(response)?;
        Ok(self.process_mxtables_for_finished(&mxtable))
    }

    // get_request_for_round1 returns choice bits from which the caller
    // can build an OT request for round 1 to compute GHASH for the HTTP request.
    pub fn get_request_for_round1(&mut self) -> Result<Vec<bool>, GhashError> {
        if self.state != ReceiverState::FinishedReceived {
            return Err(GhashError::OutOfORder);
        }
        self.state = ReceiverState::Round1Sent;
        Ok(self.get_ybits_for_round(1).concat())
    }

    // process_response_for_round1 processes masked x tables received via OT
    // for round 1 needed to compute GHASH for the HTTP request.
    pub fn process_response_for_round1(&mut self, response: &Vec<u128>) -> Result<(), GhashError> {
        if self.state != ReceiverState::Round1Sent {
            return Err(GhashError::OutOfORder);
        }
        self.state = ReceiverState::Round1Received;
        let mxtables = self.flat_to_mxtables(response)?;
        self.process_mxtables_for_round(&mxtables, 1);
        Ok(())
    }

    // get_request_for_round2 returns choice bits from which the caller
    // can build an OT request for round 2 to compute GHASH for the HTTP request.
    pub fn get_request_for_round2(&mut self) -> Result<Vec<bool>, GhashError> {
        if self.state != ReceiverState::Round1Received {
            return Err(GhashError::OutOfORder);
        }
        self.state = ReceiverState::Round2Sent;
        Ok(self.get_ybits_for_round(2).concat())
    }

    // process_response_for_round2 processes masked x tables received via OT
    // for round 2 needed to compute GHASH for the HTTP request.
    pub fn process_response_for_round2(&mut self, response: &Vec<u128>) -> Result<(), GhashError> {
        if self.state != ReceiverState::Round2Sent {
            return Err(GhashError::OutOfORder);
        }
        self.state = ReceiverState::Round2Received;
        let mxtables = self.flat_to_mxtables(response)?;
        self.process_mxtables_for_round(&mxtables, 2);
        Ok(())
    }

    // get_request_for_block_aggregation returns choice bits from which the caller
    // can build an OT request for the block aggregation method needed to compute
    // GHASH for the HTTP request.
    pub fn get_request_for_block_aggregation(&mut self) -> Result<Vec<bool>, GhashError> {
        // round2 is optional
        if !(self.state == ReceiverState::Round1Received
            || self.state == ReceiverState::Round2Received)
        {
            return Err(GhashError::OutOfORder);
        }
        self.state = ReceiverState::BlockAggregationSent;
        Ok(self.get_ybits_for_block_aggr().concat())
    }

    // process_response_for_block_aggregation processes masked x tables received
    // via OT for the block aggregation method needed to compute GHASH for the
    // HTTP request.
    pub fn process_response_for_block_aggregation(
        &mut self,
        response: &Vec<u128>,
    ) -> Result<u128, GhashError> {
        if self.state != ReceiverState::BlockAggregationSent {
            return Err(GhashError::OutOfORder);
        }
        self.state = ReceiverState::BlockAggregationReceived;
        let mxtables = self.flat_to_mxtables(response)?;
        let share = self.process_mxtables_for_block_aggr(&mxtables);
        Ok(share)
    }

    // set_blocks sets GHASH input blocks. Although blocks were set in new(),
    // those were blocks for the Client/Server_Finished. We set new blocks here
    // in order to compute GHASH for TLS application records.
    pub fn set_blocks(&mut self, blocks: Vec<u128>) -> Result<(), GhashError> {
        if blocks.len() > 1026 {
            return Err(GhashError::MaxBlocksExceeded);
        }
        self.c.blocks = blocks;
        // update values because block count changed
        self.c.max_odd_power = find_max_odd_power(self.c.blocks.len() as u16);
        self.c.powers = square_all(&self.c.powers, self.c.blocks.len() as u16);
        Ok(())
    }

    // only used for testing to check the internal state of powers
    pub fn get_powers(&self) -> BTreeMap<u16, u128> {
        self.c.powers.clone()
    }

    // flat_to_mxtables converts a flat vector into a vector of MXTable
    fn flat_to_mxtables(&mut self, flat: &Vec<u128>) -> Result<Vec<MXTable>, GhashError> {
        if flat.len() % 128 != 0 {
            return Err(GhashError::FlatWrongLength);
        }
        let count = flat.len() / 128;
        let mut mxtables: Vec<MXTable> = Vec::with_capacity(count);
        for chunk in flat.chunks(128) {
            mxtables.push(chunk.to_vec());
        }
        Ok(mxtables)
    }

    // get_ybits_for_finished returns bits of Y needed to build either the TLS's
    // Client_Finished or Server_Finished. Note that one instance of
    // GhashReceiver must be used for CF (and subsequent HTTP request) and a
    // separate instance must be used for SF.
    fn get_ybits_for_finished(&mut self) -> Vec<YBits> {
        vec![
            u8vec_to_boolvec(&self.c.powers[&1].to_be_bytes()),
            u8vec_to_boolvec(&self.c.powers[&2].to_be_bytes()),
        ]
    }

    // process_mxtable_finished takes masked xtables and computes our
    // share of powers[3] needed for Client/Server_Finished. Then it multiplies
    // each block with the corresponding
    // power and outputs our share of GHASH for the CF or SF message.
    fn process_mxtables_for_finished(&mut self, mxtables: &Vec<MXTable>) -> u128 {
        // the XOR sum of all masked xtables' values plus H^1*H^2 is our share of H^3
        self.c.powers.insert(
            3,
            xor_sum(&mxtables[0])
                ^ xor_sum(&mxtables[1])
                ^ block_mult(self.c.powers[&1], self.c.powers[&2]),
        );
        let ghash_share = block_mult(self.c.blocks[0], self.c.powers[&3])
            ^ block_mult(self.c.blocks[1], self.c.powers[&2])
            ^ block_mult(self.c.blocks[2], self.c.powers[&1]);
        ghash_share
    }

    // get_ybits_for_round returns Receiver's Y bits for a
    // given round of communication.
    fn get_ybits_for_round(&mut self, round_no: u8) -> Vec<YBits> {
        assert!(round_no == 1 || round_no == 2);
        let mut bits: Vec<YBits> = Vec::new();
        for (key, value) in self.c.strategies[(round_no - 1) as usize].iter() {
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

    // process_mxtables_for_round processed masked X tables for a given round
    // of communication.
    fn process_mxtables_for_round(&mut self, mxtables: &Vec<MXTable>, round_no: u8) {
        for (count, (power, factors)) in self.c.strategies[(round_no - 1) as usize]
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

    // get_ybits_for_block_aggr returns Receiver's bits of Y for the block
    // aggregation method.
    fn get_ybits_for_block_aggr(&mut self) -> Vec<YBits> {
        let share1 = multiply_powers_and_blocks(&self.c.powers, &self.c.blocks);
        let (aggregated, share2) = block_aggregation(&self.c.powers, &self.c.blocks);
        let choice_bits = block_aggregation_bits(&self.c.powers, &aggregated);
        self.temp_share = share1 ^ share2;
        choice_bits
    }

    // process_mxtables_for_block_aggr processes masked x tables for the block
    // aggregation method.
    fn process_mxtables_for_block_aggr(&mut self, mxtables: &Vec<MXTable>) -> u128 {
        let mut share = 0u128;
        for table in mxtables.iter() {
            share ^= xor_sum(table);
        }
        self.temp_share ^ share
    }
}
