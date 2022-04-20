// implements the GHASH sender. This is the party which holds the X value of
// block multiplication. The sender acts as the sender of the Oblivious
// Transfer and sends masked x_table entries obliviously for each
// bit of Y received from the GHASH receiver.

use super::common::GhashCommon;
use super::errors::*;
use super::utils::{
    block_aggregation, block_aggregation_mxtables, block_mult, find_max_odd_power, free_square,
    masked_xtable, multiply_powers_and_blocks, square_all,
};
use super::MXTableFull;
use rand::{CryptoRng, Rng};
use std::collections::BTreeMap;

#[derive(PartialEq)]
pub enum SenderState {
    Initialized,
    FinishedReceived,
    // There may be 1 or 2 rounds depending on GHASH block count
    Round1Received,
    Round2Received,
    BlockAggregationReceived,
}

pub struct GhashSender<R> {
    c: GhashCommon,
    // rng is random number generator
    rng: R,
    state: SenderState,
}

impl<R: Rng + CryptoRng> GhashSender<R> {
    pub fn new(rng: R, ghash_key_share: u128, blocks: Vec<u128>) -> Self {
        let c = GhashCommon::new(ghash_key_share, blocks);
        Self {
            c,
            rng,
            state: SenderState::Initialized,
        }
    }

    // get_response_for_finished returns masked x tables which must be sent via
    // OT and also our GHASH share for the Client/Server_Finished.
    pub fn get_response_for_finished(&mut self) -> Result<(Vec<[u128; 2]>, u128), GhashError> {
        if self.state != SenderState::Initialized {
            return Err(GhashError::OutOfORder);
        }
        self.state = SenderState::FinishedReceived;
        let (mxtables, share) = self.get_mxtables_for_finished();
        Ok((mxtables.concat(), share))
    }

    // get_response_for_round1 returns masked x tables which must be sent via
    // OT to compute GHASH for the HTTP request.
    pub fn get_response_for_round1(&mut self) -> Result<Vec<[u128; 2]>, GhashError> {
        if self.state != SenderState::FinishedReceived {
            return Err(GhashError::OutOfORder);
        }
        self.state = SenderState::Round1Received;
        Ok(self.get_mxtables_for_round(1).concat())
    }

    // get_response_for_round2 returns masked x tables which must be sent via
    // OT to compute GHASH for the HTTP request.
    pub fn get_response_for_round2(&mut self) -> Result<Vec<[u128; 2]>, GhashError> {
        if self.state != SenderState::Round1Received {
            return Err(GhashError::OutOfORder);
        }
        self.state = SenderState::Round2Received;
        Ok(self.get_mxtables_for_round(2).concat())
    }

    // get_response_for_round2 returns masked x tables which must be sent via
    // OT to compute GHASH for the HTTP request.
    pub fn get_response_for_block_aggregation(
        &mut self,
    ) -> Result<(Vec<[u128; 2]>, u128), GhashError> {
        // round2 is optional
        if !(self.state == SenderState::Round1Received || self.state == SenderState::Round2Received)
        {
            return Err(GhashError::OutOfORder);
        }
        self.state = SenderState::BlockAggregationReceived;
        let (mxtables, share) = self.get_mxtables_for_block_aggr();
        Ok((mxtables.concat(), share))
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

    // only used for testing
    pub fn get_powers(&self) -> BTreeMap<u16, u128> {
        self.c.powers.clone()
    }

    // get_mxtables_for_finished returns masked xtable values needed to
    // compute GHASH in 2PC for TLS's Client_Finished and Server_Finished and
    // also returns our GHASH share.
    // Since the receiver (R) sends bits for his powers in ascending order, we need to
    // accomodate that order, i.e. if we need to multiply R's H^1 by
    // our H^2 and then multiply R's H^2 by our H^1, then we return [xtable
    // for H^2 + xtable for H^1].
    fn get_mxtables_for_finished(&mut self) -> (Vec<MXTableFull>, u128) {
        self.c.powers.insert(2, free_square(self.c.powers[&1]));
        let (masked1, h3_share1) = masked_xtable(&mut self.rng, self.c.powers[&1]);
        let (masked2, h3_share2) = masked_xtable(&mut self.rng, self.c.powers[&2]);

        self.c.powers.insert(
            3,
            block_mult(self.c.powers[&1], self.c.powers[&2]) ^ h3_share1 ^ h3_share2,
        );
        let ghash_share = block_mult(self.c.blocks[0], self.c.powers[&3])
            ^ block_mult(self.c.blocks[1], self.c.powers[&2])
            ^ block_mult(self.c.blocks[2], self.c.powers[&1]);

        (vec![masked2, masked1], ghash_share)
    }

    // get_mxtables_for_round returns masked x tables for either round 1 or
    // round 2.
    fn get_mxtables_for_round(&mut self, round_no: u8) -> Vec<MXTableFull> {
        assert!(round_no == 1 || round_no == 2);
        let mut all_mxtables: Vec<MXTableFull> = Vec::new();
        for (key, value) in self.c.strategies[(round_no - 1) as usize].clone().iter() {
            if *key > self.c.max_odd_power {
                break;
            }
            // since receiver sends bits in ascending order: factor1, factor2,
            // we must return xtables in descending order factor2, factor1;
            let factor1 = self.c.powers[&(value[0] as u16)];
            let factor2 = self.c.powers[&(value[1] as u16)];
            let (mxtable1, sum1) = masked_xtable(&mut self.rng, factor1);
            let (mxtable2, sum2) = masked_xtable(&mut self.rng, factor2);
            all_mxtables.push(mxtable2);
            all_mxtables.push(mxtable1);

            // sender's share of power <key> is the locally computed term plus sums
            // of masks of each cross-term.
            let local_term = block_mult(factor1, factor2);
            self.c.powers.insert(*key as u16, local_term ^ sum1 ^ sum2);
        }
        // since we just added a few new shares of powers, we need to square them
        self.c.powers = square_all(&self.c.powers, self.c.blocks.len() as u16);
        all_mxtables
    }

    // get_mxtables_for_block_aggr returns masked x tables for the block
    // aggregation method and our final GHASH share.
    fn get_mxtables_for_block_aggr(&mut self) -> (Vec<MXTableFull>, u128) {
        let share1 = multiply_powers_and_blocks(&self.c.powers, &self.c.blocks);
        let (aggregated, share2) = block_aggregation(&self.c.powers, &self.c.blocks);
        let (mxtables, share3) =
            block_aggregation_mxtables(&mut self.rng, &self.c.powers, &aggregated);
        let ghash_share = share1 ^ share2 ^ share3;
        (mxtables, ghash_share)
    }
}
