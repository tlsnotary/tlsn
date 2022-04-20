use super::utils::{find_max_odd_power, square_all};
use std::collections::BTreeMap;

// GhashCommon is common to both GhashSender and GhashReceiver
pub struct GhashCommon {
    // blocks are input blocks for GHASH. In TLS the first block is AAD,
    // the middle blocks are AES blocks - the ciphertext, the last block
    // is len(AAD)+len(ciphertext)
    pub blocks: Vec<u128>,
    // powers are our XOR shares of the powers of H (H is the GHASH key).
    // We need as many powers as there blocks. Value at key==1 corresponds to the share
    // of H^1, value at key==2 to the share of H^2 etc.
    pub powers: BTreeMap<u16, u128>,
    // max_odd_power is the maximum odd power that we'll need to compute
    // GHASH in 2PC using Block Aggregation
    pub max_odd_power: u8,
    // strategies are initialized in ::new(). See comments there.
    pub strategies: [BTreeMap<u8, [u8; 2]>; 2],
}

impl GhashCommon {
    pub fn new(ghash_key_share: u128, blocks: Vec<u128>) -> Self {
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

        Self {
            max_odd_power,
            blocks,
            powers,
            strategies: [strategy1, strategy2],
        }
    }
}
