use super::{
    block_aggregation, block_aggregation_bits, multiply_powers_and_blocks, GhashCommon, YBits,
};
use mpc_core::utils::u8vec_to_boolvec;

pub trait Received: common::Common {
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
}

pub trait Sent: common::Common {
    const ROUND: usize;

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

    /// Processes masked X tables for the block aggregation method.
    fn process_mxtables_for_block_aggr(&mut self, mxtables: &Vec<MXTable>) {
        let mut share = 0u128;
        for table in mxtables.iter() {
            share ^= xor_sum(table);
        }
        self.c.temp_share = Some(self.c.temp_share.unwrap() ^ share);
    }
}

pub struct Initialized {
    pub common: GhashCommon,
}

impl Received for Initialized {
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
}

impl Sent for Initialized {
    const ROUND: usize = 1;
}

pub struct Round1 {
    pub common: GhashCommon,
}

impl Received for Round1 {
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
}

impl Sent for Round1 {
    const ROUND: usize = 2;
}

pub struct Round2 {
    pub common: GhashCommon,
}

impl Received for Round2 {
    const ROUND: usize = 2;

    fn is_next_round_needed(&self) -> bool {
        // after round 2 we will have a max of up to 19 consequitive odd powers
        // which allows us to get 339 powers with block aggregation, see max_htable
        // in utils::find_max_odd_power()
        self.common.blocks.len() > 339
    }
}

impl Sent for Round2 {
    const ROUND: usize = 3;
}

pub struct Round3 {
    pub common: GhashCommon,
}

impl Received for Round3 {
    const ROUND: usize = 3;

    fn is_next_round_needed(&self) -> bool {
        false
    }
}

impl Sent for Round3 {
    const ROUND: usize = 4;
}

mod common {
    use super::GhashCommon;

    pub trait Common {
        fn common(&self) -> &GhashCommon;
        fn common_mut(&mut self) -> &mut GhashCommon;
    }
    impl Common for super::Initialized {
        fn common(&self) -> &GhashCommon {
            &self.common
        }

        fn common_mut(&mut self) -> &mut GhashCommon {
            &mut self.common
        }
    }
    impl Common for super::Round1 {
        fn common(&self) -> &GhashCommon {
            &self.common
        }

        fn common_mut(&mut self) -> &mut GhashCommon {
            &mut self.common
        }
    }
    impl Common for super::Round2 {
        fn common(&self) -> &GhashCommon {
            &self.common
        }

        fn common_mut(&mut self) -> &mut GhashCommon {
            &mut self.common
        }
    }
    impl Common for super::Round3 {
        fn common(&self) -> &GhashCommon {
            &self.common
        }

        fn common_mut(&mut self) -> &mut GhashCommon {
            &mut self.common
        }
    }
}
