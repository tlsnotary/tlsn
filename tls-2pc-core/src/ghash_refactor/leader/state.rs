use super::{
    block_aggregation, block_aggregation_bits, multiply_powers_and_blocks, GhashCommon, YBits,
};
use mpc_core::utils::u8vec_to_boolvec;

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Initialized {}
    impl Sealed for super::Round1 {}
    impl Sealed for super::Round2 {}
    impl Sealed for super::Round3 {}
}

pub trait State: sealed::Sealed {
    const ROUND: usize;

    fn is_next_round_needed(&self) -> bool;

    /// Returns Y bits for a given round of communication
    fn y_bits(&self) -> Vec<YBits> {
        let mut bits: Vec<YBits> = Vec::new();
        for (key, value) in self.common().strategies[(Self::ROUND - 2) as usize].iter() {
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

    fn common(&self) -> &GhashCommon;
    fn common_mut(&mut self) -> &mut GhashCommon;
}

pub struct Initialized {
    pub common: GhashCommon,
}
impl State for Initialized {
    const ROUND: usize = 0;

    /// Checks if the next round is needed for the GHASH computation
    fn is_next_round_needed(&self) -> bool {
        // block agregation is always used except for very small block count
        // where powers from round 1 are sufficient to perform direct multiplication
        // of blocks by powers
        self.common.blocks.len() > 4
    }

    /// Returning Y bits in this state is not supported
    /// Never called
    fn y_bits(&self) -> Vec<YBits> {
        unimplemented!()
    }

    fn common(&self) -> &GhashCommon {
        &self.common
    }

    fn common_mut(&mut self) -> &mut GhashCommon {
        &mut self.common
    }
}

pub struct Round1 {
    pub common: GhashCommon,
}
impl State for Round1 {
    const ROUND: usize = 1;

    fn is_next_round_needed(&self) -> bool {
        // after round 1 we will have consecutive powers 1,2,3 which is enough
        // to compute GHASH for 19 blocks with block aggregation.
        self.common.blocks.len() > 19
    }

    /// Returns Y bits to compute H^3.
    fn y_bits(&self) -> Vec<YBits> {
        vec![
            u8vec_to_boolvec(&self.common().powers[&1].to_be_bytes()),
            u8vec_to_boolvec(&self.common().powers[&2].to_be_bytes()),
        ]
    }

    fn common(&self) -> &GhashCommon {
        &self.common
    }

    fn common_mut(&mut self) -> &mut GhashCommon {
        &mut self.common
    }
}

pub struct Round2 {
    pub common: GhashCommon,
}
impl State for Round2 {
    const ROUND: usize = 2;

    fn is_next_round_needed(&self) -> bool {
        // after round 2 we will have a max of up to 19 consequitive odd powers
        // which allows us to get 339 powers with block aggregation, see max_htable
        // in utils::find_max_odd_power()
        self.common.blocks.len() > 339
    }

    fn common(&self) -> &GhashCommon {
        &self.common
    }

    fn common_mut(&mut self) -> &mut GhashCommon {
        &mut self.common
    }
}

pub struct Round3 {
    pub common: GhashCommon,
}
impl State for Round3 {
    const ROUND: usize = 3;

    fn is_next_round_needed(&self) -> bool {
        false
    }

    fn common(&self) -> &GhashCommon {
        &self.common
    }

    fn common_mut(&mut self) -> &mut GhashCommon {
        &mut self.common
    }
}
