pub mod follower;
pub mod leader;
mod utils;

use std::collections::BTreeMap;
use utils::{find_max_odd_power, find_sum, square_all};

/// YBits are Master's bits of Y in big-endian. Based on these bits
/// Master will send MXTable via OT.
/// The convention for the returned Y bits:
/// A) powers are in an ascending order: first powers[1], then powers[2] etc.
/// B) bits of each power are in big-endian.
type YBits = Vec<bool>;

/// MXTableFull is masked XTable which Slave has at the beginning of OT.
/// MXTableFull must not be revealed to Master.
type MXTableFull = Vec<[u128; 2]>;

/// MXTable is a masked x table which Master will end up having after OT.
type MXTable = Vec<u128>;

/// GhashCommon is common to both Master and Slave
pub struct GhashCommon {
    /// blocks are input blocks for GHASH. In TLS the first block is AAD,
    /// the middle blocks are AES blocks - the ciphertext, the last block
    /// is len(AAD)+len(ciphertext)
    pub blocks: Vec<u128>,
    /// powers are our XOR shares of the powers of H (H is the GHASH key).
    /// We need as many powers as there blocks. Value at key==1 corresponds to the share
    /// of H^1, value at key==2 to the share of H^2 etc.
    pub powers: BTreeMap<u16, u128>,
    /// max_odd_power is the maximum odd power that we'll need to compute
    /// GHASH in 2PC using Block Aggregation
    pub max_odd_power: u8,
    /// strategies are initialized in ::new(). See comments there.
    pub strategies: [BTreeMap<u8, [u8; 2]>; 2],
    /// temp_share is used to save an intermediate GHASH share
    pub temp_share: Option<u128>,
}

impl GhashCommon {
    fn new(ghash_key_share: u128, blocks: Vec<u128>) -> Result<Self, GhashError> {
        if blocks.len() < 3 || blocks.len() > 1026 {
            return Err(GhashError::BlockCountWrong);
        }
        let mut powers = BTreeMap::new();
        // GHASH key is our share H^1
        powers.insert(1, ghash_key_share);
        let max_odd_power = find_max_odd_power(blocks.len() as u16);
        powers = square_all(&powers, blocks.len() as u16);

        // strategy1 and startegy2 are only relevant for the Block Aggregation method.
        // They show what existing shares of the powers of H (H is the GHASH key) we
        // will be multiplying (value[0] and value[1]) to obtain other odd shares (<key>).
        // Max sequential odd share that we can obtain on first round of
        // communication is 19. We already have 1) shares of H^1, H^2, H^3 from
        // the Client Finished message and 2) squares of those 3 shares.
        // Note that "sequential" is a keyword here. We can't obtain 21 but we
        // indeed can obtain 25==24+1, 33==32+1 etc. However with 21 missing,
        // even if we have 25,33,etc, there will be a gap and we will not be able
        // to obtain all the needed shares by Block Aggregation.

        // We request OT for each share in each pair of the strategy, i.e. for
        // shares: 4,1,4,3,8,1, etc. Even though it would be possible to introduce
        // optimizations in order to avoid requesting OT for the same share more
        // than once, that would only save us ~2000 OT instances at the cost of
        // complicating the code.

        let strategy1: BTreeMap<u8, [u8; 2]> = BTreeMap::from([
            (5, [4, 1]),
            (7, [4, 3]),
            (9, [8, 1]),
            (11, [8, 3]),
            (13, [12, 1]),
            (15, [12, 3]),
            (17, [16, 1]),
            (19, [16, 3]),
        ]);
        let strategy2: BTreeMap<u8, [u8; 2]> = BTreeMap::from([
            (21, [17, 4]),
            (23, [17, 6]),
            (25, [17, 8]),
            (27, [19, 8]),
            (29, [17, 12]),
            (31, [19, 12]),
            (33, [17, 16]),
            (35, [19, 16]),
        ]);

        Ok(Self {
            max_odd_power,
            blocks,
            powers,
            strategies: [strategy1, strategy2],
            temp_share: Some(0u128),
        })
    }

    /// Returns the amount of Oblivious Transfer instances needed to complete
    /// the protocol. The purpose is to inform the OT layer.
    fn calculate_ot_count(&mut self) -> usize {
        let mut powers: BTreeMap<u16, u128> = BTreeMap::new();
        // only 2 2PC multiplications in round 1
        let r1count = 2;
        powers.insert(1, 0u128);
        powers.insert(2, 0u128);
        powers.insert(3, 0u128);
        // since we just added a few new shares of powers, we need to square them
        self.powers = square_all(&powers, self.blocks.len() as u16);

        // merge 2 strategies maps into 1
        let strategy: BTreeMap<u8, [u8; 2]> = self.strategies[0]
            .clone()
            .into_iter()
            .chain(self.strategies[1].clone())
            .collect();
        // number of multiplications in rounds 2 and 3
        let mut r2and3count = 0;
        for (key, _) in strategy.iter() {
            if *key > self.max_odd_power {
                break;
            };
            powers.insert(*key as u16, 0u128);
            r2and3count += 2;
        }
        // since we just added a few new shares of powers, we need to square them
        powers = square_all(&powers, self.blocks.len() as u16);

        let mut aggregated: BTreeMap<u16, u128> = BTreeMap::new();
        for i in 1..self.blocks.len() + 1 {
            if powers.get(&(i as u16)) != None {
                continue;
            }
            let (small, _) = find_sum(&powers, i as u16);
            // initialize the value if it doesn't exist
            if aggregated.get(&small) == None {
                aggregated.insert(small, 0u128);
            }
        }
        let r4count = aggregated.len() * 2;
        // each multiplication requires 128 instances of Oblivious Transfer
        (r1count + r2and3count + r4count) * 128
    }

    fn is_round2_needed(&self) -> bool {
        // after round 1 we will have consecutive powers 1,2,3 which is enough
        // to compute GHASH for 19 blocks with block aggregation.
        self.blocks.len() > 19
    }

    fn is_round3_needed(&self) -> bool {
        // after round 2 we will have a max of up to 19 consequitive odd powers
        // which allows us to get 339 powers with block aggregation, see max_htable
        // in utils::find_max_odd_power()
        self.blocks.len() > 339
    }

    fn is_only_1_round(&self) -> bool {
        // block agregation is always used except for very small block count
        // where powers from round 1 are sufficient to perform direct multiplication
        // of blocks by powers
        self.blocks.len() <= 4
    }

    #[cfg(test)]
    fn powers(&self) -> &BTreeMap<u16, u128> {
        &self.powers
    }
}

/// Errors that may occur when using ghash module
#[derive(Debug, thiserror::Error)]
pub enum GhashError {
    #[error("Message was received out of order")]
    OutOfOrder,
    #[error("The other party sent data of wrong size")]
    DataLengthWrong,
    #[error("Tried to pass unsupported block count")]
    BlockCountWrong,
    #[error("Tried to finalize before the protocol was complete")]
    FinalizeCalledTooEarly,
}
