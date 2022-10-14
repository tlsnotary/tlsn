use super::{
    block_aggregation, block_aggregation_bits, block_mult, multiply_powers_and_blocks, square_all,
    xor_sum, Common, GhashCommon, YBits,
};
use crate::ghash_refactor::MXTable;
use crate::impl_ghash_common;
use mpc_core::utils::u8vec_to_boolvec;

pub trait LeaderSend: Common {
    const ROUND: usize;

    /// Returns Y bits for a given round of communication
    fn y_bits_for_next_round(&self) -> Vec<YBits> {
        let mut bits: Vec<YBits> = Vec::new();
        for (key, value) in
            self.common().strategies[(<Self as LeaderSend>::ROUND - 1) as usize].iter()
        {
            if *key > self.common().max_odd_power {
                break;
            }
            bits.push(u8vec_to_boolvec(
                &self.common().powers[&(value[0] as u16)].to_be_bytes(),
            ));
            bits.push(u8vec_to_boolvec(
                &self.common().powers[&(value[1] as u16)].to_be_bytes(),
            ));
        }
        bits
    }

    /// Returns Y bits for the block aggregation method
    fn ybits_for_block_aggr(&mut self) -> Vec<YBits> {
        let share1 = multiply_powers_and_blocks(&self.common().powers, &self.common().blocks);
        let (aggregated, share2) = block_aggregation(&self.common().powers, &self.common().blocks);
        let choice_bits = block_aggregation_bits(&self.common().powers, &aggregated);
        self.common_mut().temp_share = Some(share1 ^ share2);
        choice_bits
    }
}

pub trait LeaderReceive: Common {
    const ROUND: usize;

    /// Processes masked X tables for a given round of communication.
    fn process_mxtables(&mut self, mxtables: &Vec<MXTable>) {
        let mut collected_shares = vec![];
        for (count, (power, factors)) in self.common().strategies[(Self::ROUND - 2) as usize]
            .iter()
            .enumerate()
        {
            if *power > self.common().max_odd_power {
                // for every key in the strategy which we processed, there
                // must have been 2 masked xtables
                assert!(count * 2 == mxtables.len());
                break;
            }
            // the XOR sum of 2 masked xtables' values plus the locally computed
            // term is our share of power
            let sum = xor_sum(&mxtables[count * 2]) ^ xor_sum(&mxtables[(count * 2) + 1]);
            let local_term = block_mult(
                self.common().powers[&(factors[0] as u16)],
                self.common().powers[&(factors[1] as u16)],
            );
            collected_shares.push((*power as u16, sum ^ local_term));
        }
        self.common_mut().powers.extend(collected_shares);
        // since we just added a few new shares of powers, we need to square them
        self.common_mut().powers =
            square_all(&self.common().powers, self.common().blocks.len() as u16);
    }

    /// Compute Ghash directly
    ///
    /// If the last round was not round 4 (i.e. there was no block
    /// aggregation), then we compute GHASH directly
    fn compute_ghash(&mut self) {
        self.common_mut().temp_share = Some(multiply_powers_and_blocks(
            &self.common().powers,
            &self.common().blocks,
        ))
    }
}

pub struct Sent;
pub struct Received;

//-----------------------------------------
pub struct Initialized<T> {
    pub common: GhashCommon,
    pub marker: std::marker::PhantomData<T>,
}

impl LeaderSend for Initialized<Received> {
    const ROUND: usize = 0;

    /// Returns Y bits to compute H^3.
    fn y_bits_for_next_round(&self) -> Vec<YBits> {
        vec![
            u8vec_to_boolvec(&self.common().powers[&1].to_be_bytes()),
            u8vec_to_boolvec(&self.common().powers[&2].to_be_bytes()),
        ]
    }

    /// Returns Y bits for the block aggregation method
    fn ybits_for_block_aggr(&mut self) -> Vec<YBits> {
        self.y_bits_for_next_round()
    }
}

//-----------------------------------------
pub struct Round1<T> {
    pub common: GhashCommon,
    pub marker: std::marker::PhantomData<T>,
}

impl LeaderSend for Round1<Received> {
    const ROUND: usize = 1;
}

impl LeaderReceive for Round1<Sent> {
    const ROUND: usize = 1;

    /// Takes masked X tables and computes our share of H^3.
    fn process_mxtables(&mut self, mxtables: &Vec<MXTable>) {
        let (powers_one, powers_two) = (self.common().powers[&1], self.common().powers[&1]);

        // the XOR sum of all masked xtables' values plus H^1*H^2 is our share of H^3
        self.common_mut().powers.insert(
            3,
            xor_sum(&mxtables[0]) ^ xor_sum(&mxtables[1]) ^ block_mult(powers_one, powers_two),
        );
        // since we just added a new share of powers, we need to square them
        self.common_mut().powers =
            square_all(&self.common().powers, self.common().blocks.len() as u16);
    }
}

//-----------------------------------------
pub struct Round2<T> {
    pub common: GhashCommon,
    pub marker: std::marker::PhantomData<T>,
}

impl LeaderSend for Round2<Received> {
    const ROUND: usize = 2;
}

impl LeaderReceive for Round2<Sent> {
    const ROUND: usize = 2;
}

//-----------------------------------------
pub struct Round3<T> {
    pub common: GhashCommon,
    pub marker: std::marker::PhantomData<T>,
}

impl LeaderSend for Round3<Received> {
    const ROUND: usize = 3;

    fn y_bits_for_next_round(&self) -> Vec<YBits> {
        unimplemented!()
    }
}

impl LeaderReceive for Round3<Sent> {
    const ROUND: usize = 3;
}

//-----------------------------------------
pub struct Round4<T> {
    pub common: GhashCommon,
    pub marker: std::marker::PhantomData<T>,
}

impl LeaderReceive for Round4<Sent> {
    const ROUND: usize = 4;

    /// Processes masked X tables for the block aggregation method.
    fn process_mxtables(&mut self, mxtables: &Vec<MXTable>) {
        let mut share = 0u128;
        for table in mxtables.iter() {
            share ^= xor_sum(table);
        }
        self.common_mut().temp_share = Some(self.common().temp_share.unwrap() ^ share);
    }

    fn compute_ghash(&mut self) {}
}

//-----------------------------------------
pub struct Finalized {
    pub common: GhashCommon,
}

//-----------------------------------------
impl_ghash_common!(Initialized<T>);
impl_ghash_common!(Round1<T>);
impl_ghash_common!(Round2<T>);
impl_ghash_common!(Round3<T>);
impl_ghash_common!(Round4<T>);
