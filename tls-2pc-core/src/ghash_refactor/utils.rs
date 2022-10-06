use crate::ghash_refactor::{MXTableFull, YBits};
use mpc_core::utils::u8vec_to_boolvec;
use rand::{CryptoRng, Rng};
use std::collections::BTreeMap;

/// R is GCM polynomial in little-endian. In hex: "E1000000000000000000000000000000"
const R: u128 = 299076299051606071403356588563077529600;

/// Galois field multiplication of two 128-bit blocks reduced by the GCM polynomial
pub fn block_mult(mut x: u128, y: u128) -> u128 {
    let mut result: u128 = 0;
    for i in (0..128).rev() {
        result ^= x * ((y >> i) & 1);
        x = (x >> 1) ^ ((x & 1) * R);
    }
    result
}

/// Returns the squared value. It is called "free" because due to the
/// property of Galois multiplication, squaring can be done locally without
/// the need for 2PC.
pub fn free_square(x: u128) -> u128 {
    block_mult(x, x)
}

/// Performs squaring of each odd power in "powers" up to and including
/// the maximum power "max" and returns an updated map of powers. Squaring
/// will be done recursively if needed, e.g if we have power == 1 and "max" is 22,
/// then 1 will be squared to get power == 2, then 2 -> 4, 4 -> 8, 8 -> 16.
/// Those powers which have already been squared will be skipped.
pub fn square_all(powers: &BTreeMap<u16, u128>, max: u16) -> BTreeMap<u16, u128> {
    let mut new_powers: BTreeMap<u16, u128> = BTreeMap::new();
    for (power, value) in powers.iter() {
        // The fact the we had earlier computed more powers that we will ever
        // need is a sign of a logic error which needs to be investigated.
        assert!(*power <= max);
        new_powers.insert(*power, *value);
        if power % 2 == 0 {
            continue;
        }
        // existing_power is the power for which we have the value.
        let mut existing_power = *power;
        while existing_power * 2 <= max {
            // check if the squaring has already been done, otherwise do it now.
            let option = powers.get(&(existing_power * 2));
            let squared_value: u128;
            if option == None {
                let value_to_square = new_powers.get(&existing_power).unwrap();
                squared_value = free_square(*value_to_square);
            } else {
                squared_value = *option.unwrap();
            }
            new_powers.insert(existing_power * 2, squared_value);
            existing_power *= 2;
        }
    }
    new_powers
}

/// Finds 2 non-equal summands which add up to the needed sum. The
/// first returned summand will be as small as possible.
/// E.g if "summands" keys are 1,2,3,5,6 and "sum_needed" is 8, then
/// the returned value would be (2,6).
pub fn find_sum(summands: &BTreeMap<u16, u128>, sum_needed: u16) -> (u16, u16) {
    for (i, _) in summands.iter() {
        for (j, _) in summands.iter() {
            if *j == *i {
                continue;
            }
            if *i + *j == sum_needed {
                return (*i, *j);
            }
        }
    }
    // Should never get here. We only call find_sum when we know in advance
    // that summands will be found.
    panic!("summands were not found")
}

/// Returns the maximum odd power that we'll need to compute GHASH in 2PC
/// using Block Aggregation, where "max" is maximum power for GHASH
/// (i.e it is the amount of GHASH blocks).
pub fn find_max_odd_power(max: u16) -> u8 {
    assert!(max <= 1026);
    // max_htable's <value> shows how many GHASH blocks can be processed
    // with Block Aggregation if we have all the sequential shares
    // starting with 1 up to and including <key>.
    // e.g. (5, 29) means that if we have shares of H^1,H^2,H^3,H^4,H^5,
    // then we can process 29 GHASH blocks.
    // max TLS record size of 16KB requires 1026 GHASH blocks
    let max_htable: BTreeMap<u8, u16> = BTreeMap::from([
        (0, 0),
        (3, 19),
        (5, 29),
        (7, 71),
        (9, 89),
        (11, 107),
        (13, 125),
        (15, 271),
        (17, 305),
        (19, 339),
        (21, 373),
        (23, 407),
        (25, 441),
        (27, 475),
        (29, 509),
        (31, 1023),
        (33, 1025),
        (35, 1027),
    ]);
    let mut out = 0u8;
    for (key, value) in max_htable.iter() {
        if *value >= max {
            out = *key;
            break;
        }
    }
    out
}

/// Multiplies GHASH blocks by the corresponding shares of powers of H and
/// returns the sum of all products. If some share is not present, the
/// corresponding block is not multiplied at this stage but it will later
/// participate in block aggregation.
pub fn multiply_powers_and_blocks(powers: &BTreeMap<u16, u128>, blocks: &Vec<u128>) -> u128 {
    let last_key = *powers.iter().last().unwrap().0;
    assert!(last_key as usize <= blocks.len());
    let mut sum = 0u128;
    for (power, value) in powers.iter() {
        // in GHASH, H^1 is multiplied with the last block, H^2 with the second to last
        // block, etc.
        sum ^= block_mult(*value, blocks[blocks.len() - (*power as usize)]);
    }
    sum
}

/// Implements the block aggregation method.
pub fn block_aggregation(
    powers: &BTreeMap<u16, u128>,
    blocks: &Vec<u128>,
) -> (BTreeMap<u16, u128>, u128) {
    let mut ghash_share = 0u128;
    let mut aggregated: BTreeMap<u16, u128> = BTreeMap::new();
    for i in 1..blocks.len() + 1 {
        if powers.get(&(i as u16)) != None {
            // we already multiplied the block with this share of power in
            // multiply_powers_and_blocks()
            continue;
        }
        // else we found a power of H which we don't have.
        let (small, big) = find_sum(&powers, i as u16);
        let block = blocks[blocks.len() - i];
        ghash_share ^= block_mult(
            block_mult(*powers.get(&small).unwrap(), *powers.get(&big).unwrap()),
            block,
        );
        // initialize the value if it doesn't exist
        if aggregated.get(&small) == None {
            aggregated.insert(small, 0u128);
        }
        // update value
        let old_value = *aggregated.get(&small).unwrap();
        aggregated.insert(
            small,
            old_value ^ block_mult(*powers.get(&big).unwrap(), block),
        );
    }
    (aggregated, ghash_share)
}

/// Returns YBits which Master needs to complete Block Aggregation.
pub fn block_aggregation_bits(
    powers: &BTreeMap<u16, u128>,
    aggregated: &BTreeMap<u16, u128>,
) -> Vec<YBits> {
    let mut all_bits: Vec<YBits> = Vec::new();
    for (power, value) in aggregated.iter() {
        // Master sends first bits of power then bits of value. Slave sends
        // masked x tables in reverse order.
        all_bits.push(u8vec_to_boolvec(
            &(*powers.get(power).unwrap()).to_be_bytes(),
        ));
        all_bits.push(u8vec_to_boolvec(&value.to_be_bytes()));
    }
    all_bits
}

/// Returns masked X tables which Slave needs to complete Block Aggregation.
pub fn block_aggregation_mxtables<R: Rng + CryptoRng>(
    rng: &mut R,
    powers: &BTreeMap<u16, u128>,
    aggregated: &BTreeMap<u16, u128>,
) -> (Vec<MXTableFull>, u128) {
    let mut all_mxtables: Vec<MXTableFull> = Vec::new();
    let mut sum = 0u128;
    for (power, value) in aggregated.iter() {
        // Slave sends first masked x table of agregated value then masked x
        // table of power value.
        let (mxtable1, sum1) = masked_xtable(rng, *value);
        let (mxtable2, sum2) = masked_xtable(rng, *powers.get(power).unwrap());
        sum ^= sum1 ^ sum2;
        all_mxtables.push(mxtable1);
        all_mxtables.push(mxtable2);
    }
    (all_mxtables, sum)
}

/// Returns a table of values of x after each of the 128 rounds of blockMult()
fn xtable(mut x: u128) -> Vec<u128> {
    let mut x_table: Vec<u128> = vec![0u128; 128];
    for i in 0..128 {
        x_table[i] = x;
        x = (x >> 1) ^ ((x & 1) * R);
    }
    x_table
}

/// Returns:
/// 1) a masked xTable from which OT response will be constructed and
/// 2) the XOR-sum of all masks which is our share of the block multiplication product
/// For each value of xTable, the masked xTable will contain 2 values:
/// 1) a random mask and
/// 2) the xTable entry masked with the random mask.
pub fn masked_xtable<R: Rng + CryptoRng>(rng: &mut R, x: u128) -> (MXTableFull, u128) {
    let x_table = xtable(x);
    // maskSum is the xor sum of all masks
    let mut mask_sum: u128 = 0;
    let mut masked_xtable: MXTableFull = vec![[0u128; 2]; 128];
    for i in 0..128 {
        let mask: u128 = rng.gen();
        mask_sum ^= mask;
        masked_xtable[i][0] = mask;
        masked_xtable[i][1] = x_table[i] ^ mask;
    }
    (masked_xtable, mask_sum)
}

/// Returns the XOR sum of all elements of the vector.
pub fn xor_sum(vec: &Vec<u128>) -> u128 {
    vec.iter().fold(0u128, |acc, x| acc ^ x)
}

/// Converts a flat vector into a vector of chunks of the needed size.
pub fn flat_to_chunks<T>(flat: &Vec<T>, chunk_size: usize) -> Vec<Vec<T>>
where
    T: Clone,
{
    let count = flat.len() / chunk_size;
    let mut vec_chunks: Vec<Vec<T>> = Vec::with_capacity(count);
    for chunk in flat.chunks(chunk_size) {
        vec_chunks.push(chunk.to_vec());
    }
    vec_chunks
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghash_rc::{
        universal_hash::{NewUniversalHash, UniversalHash},
        GHash,
    };
    use rand::SeedableRng;
    use rand::{thread_rng, Rng};
    use rand_chacha::ChaCha12Rng;
    use std::convert::TryInto;

    #[test]
    fn test_block_mult() {
        let mut rng = thread_rng();
        let x: u128 = rng.gen();
        let y: u128 = rng.gen();
        assert_eq!(block_mult(x, y), rust_crypto_ghash(x, &vec![y]));
    }

    #[test]
    fn test_free_square() {
        let mut rng = thread_rng();
        let x: u128 = rng.gen();
        assert_eq!(free_square(x), rust_crypto_ghash(x, &vec![x]));
    }

    #[test]
    fn test_square_all() {
        let mut powers_keys: Vec<u16> = vec![1, 3, 5, 6];
        let mut max_power = 8;
        let mut powers = setup_square_all(powers_keys);
        let mut res = square_all(&powers, max_power);
        let mut res_keys: Vec<u16> = res.keys().cloned().collect();
        let mut res_values: Vec<u128> = res.values().cloned().collect();
        assert_eq!(res_keys, vec![1, 2, 3, 4, 5, 6, 8]);
        assert_eq!(
            res_values,
            vec![
                12346,
                37384537381450758925419573570612497787,
                12348,
                330354857586696702251049094163216396600,
                12350,
                12351,
                226635212255694396134298606764692048245
            ]
        );

        powers_keys = vec![1, 101];
        max_power = 255;
        powers = setup_square_all(powers_keys);
        res = square_all(&powers, max_power);
        res_keys = res.keys().cloned().collect();
        res_values = res.values().cloned().collect();
        assert_eq!(res_keys, vec![1, 2, 4, 8, 16, 32, 64, 101, 128, 202]);
        assert_eq!(
            res_values,
            vec![
                12346,
                37384537381450758925419573570612497787,
                330354857586696702251049094163216396600,
                226635212255694396134298606764692048245,
                57435732663173249101181542372863021389,
                221430791223604693286277902449016542898,
                102715545892785352441374614451375486130,
                12446,
                308951395680463668816102109032313818778,
                144387391042136486694176041923180290643
            ]
        );
    }

    #[test]
    #[should_panic]
    fn test_square_all_should_panic() {
        let powers_keys: Vec<u16> = vec![1, 3, 5, 6, 9];
        let max_power = 8;
        let powers = setup_square_all(powers_keys);
        // will panick because we have power 9 when max needed is 8
        square_all(&powers, max_power);
    }

    #[test]
    fn test_find_sum() {
        let summands = setup_find_sum();
        assert_eq!(find_sum(&summands, 8), (3, 5));
        assert_eq!(find_sum(&summands, 14), (5, 9));
        assert_eq!(find_sum(&summands, 21), (6, 15));
    }

    #[test]
    #[should_panic]
    fn test_find_sum_should_panic() {
        let summands = setup_find_sum();
        // will panick because summands must be non-equal, so (15, 15) is not
        // allowed
        find_sum(&summands, 30);
        // will panick because no two summands add up to 25
        find_sum(&summands, 25);
    }

    #[test]
    fn test_find_max_odd_power() {
        assert_eq!(find_max_odd_power(1), 3);
        assert_eq!(find_max_odd_power(20), 5);
        assert_eq!(find_max_odd_power(100), 11);
        assert_eq!(find_max_odd_power(1000), 31);
    }

    #[test]
    fn test_multiply_powers_and_blocks() {
        let mut rng = thread_rng();
        let block_count = 10;
        let h: u128 = rng.gen();
        let powers_of_h = compute_expected_powers(h, 10);
        let mut powers: BTreeMap<u16, u128> = BTreeMap::new();
        let mut blocks: Vec<u128> = Vec::new();
        // init all powers and all blocks
        for i in 0..block_count {
            powers.insert(i + 1, powers_of_h[(i + 1) as usize]);
            blocks.push(rng.gen());
        }
        let result = multiply_powers_and_blocks(&powers, &blocks);
        assert_eq!(result, rust_crypto_ghash(h, &blocks));
    }

    #[test]
    #[should_panic]
    fn test_multiply_powers_and_blocks_should_panic() {
        let mut rng = thread_rng();
        let block_count = 10;
        let h: u128 = rng.gen();
        let powers_of_h = compute_expected_powers(h, block_count);
        let mut powers: BTreeMap<u16, u128> = BTreeMap::new();
        let mut blocks: Vec<u128> = Vec::new();
        // init all powers and all blocks
        for i in 0..block_count {
            powers.insert(i + 1, powers_of_h[(i + 1) as usize]);
            blocks.push(rng.gen());
        }
        // insert an extra power to have more powers than blocks which is a
        // sign of a logic error.
        powers.insert(
            block_count + 1,
            block_mult(powers_of_h[block_count as usize], h),
        );
        multiply_powers_and_blocks(&powers, &blocks);
    }

    #[test]
    fn test_block_aggregation() {
        let h: u128 = 123456;
        let block_count = 10;
        let powers_of_h = compute_expected_powers(h, block_count);
        let mut powers_map: BTreeMap<u16, u128> = BTreeMap::new();
        let mut blocks: Vec<u128> = Vec::with_capacity(block_count as usize);
        for i in 1..block_count + 1 {
            powers_map.insert(i, powers_of_h[i as usize]);
            blocks.push(1234567 + i as u128);
        }
        // all powers are in place, so no block aggregation will happen
        assert_eq!(
            block_aggregation(&powers_map, &blocks),
            (BTreeMap::new(), 0)
        );
        // remove some powers
        powers_map.remove(&5);
        powers_map.remove(&7);
        let mut expected_map: BTreeMap<u16, u128> = BTreeMap::new();
        expected_map.insert(1, 6529972824624832318862907648013721286);
        assert_eq!(
            block_aggregation(&powers_map, &blocks),
            (expected_map, 315833047958356732231847338615588728787)
        );
    }

    #[test]
    fn test_block_aggregation_bits() {
        let mut powers_map: BTreeMap<u16, u128> = BTreeMap::new();
        let mut aggregated_map: BTreeMap<u16, u128> = BTreeMap::new();
        powers_map.insert(1, 256);
        aggregated_map.insert(1, 512);
        let mut expected: [[bool; 128]; 2] = [[false; 128]; 2];
        expected[0][128 - 9] = true; // set bit for 256
        expected[1][128 - 10] = true; // set bit for 512
        assert_eq!(
            expected.concat(),
            block_aggregation_bits(&powers_map, &aggregated_map).concat()
        );
    }

    #[test]
    fn test_block_aggregation_mxtables() {
        let mut rng = ChaCha12Rng::seed_from_u64(12345);

        let mut powers_map: BTreeMap<u16, u128> = BTreeMap::new();
        let mut aggregated_map: BTreeMap<u16, u128> = BTreeMap::new();
        powers_map.insert(1, 256);
        aggregated_map.insert(1, 512);
        let mut expected: [[bool; 128]; 2] = [[false; 128]; 2];
        expected[0][128 - 9] = true; // set bit for 256
        expected[1][128 - 10] = true; // set bit for 512
        let (mxtables, share) = block_aggregation_mxtables(&mut rng, &powers_map, &aggregated_map);
        assert_eq!(share, 119435139769675579125133100514879089925);
        // since mxtables output is huge, we check only a few arbitrary elements of it
        assert_eq!(
            mxtables.concat()[23],
            [
                87470858790173581075227934021272140429,
                87445059565157736150448673117636328077
            ]
        );
        assert_eq!(
            mxtables.concat()[54],
            [
                332311817981764475918232627385210634271,
                332311817981747626514621748491088166943
            ]
        );
        assert_eq!(
            mxtables.concat()[10],
            [
                111226209635646018502889366408372405024,
                237502869235213026428751037135005139744
            ]
        );
    }

    #[test]
    fn test_xtable() {
        let result = xtable(123456u128);
        // since xtable output is huge, we check only a few arbitrary elements of it
        assert_eq!(result[0], 123456);
        assert_eq!(result[39], 57076772936301564299567746252800);
        assert_eq!(result[111], 12086476800);
    }

    #[test]
    fn test_masked_xtable() {
        let mut rng = thread_rng();
        let x: u128 = rng.gen();
        let y: u128 = rng.gen();
        let expected = block_mult(x, y);
        assert_eq!(expected, product_from_shares(x, y));

        // corrupt some bytes of y value
        let mut bad_bytes = y.to_be_bytes();
        bad_bytes[5] = bad_bytes[5].checked_add(1).unwrap_or_default();
        bad_bytes[10] = bad_bytes[10].checked_add(1).unwrap_or_default();
        bad_bytes[15] = bad_bytes[15].checked_add(1).unwrap_or_default();
        let bad = u128::from_be_bytes(bad_bytes);
        assert_ne!(expected, product_from_shares(x, bad));
    }

    #[test]
    fn test_xor_sum() {
        let mut rng = thread_rng();
        let mut summands: Vec<u128> = Vec::new();
        for _i in 0..300 {
            let rand = rng.gen();
            summands.push(rand);
            summands.push(rand);
        }
        // xoring the same value twice should result in zero
        assert_eq!(xor_sum(&summands), 0);
        summands.push(123456);
        assert_eq!(xor_sum(&summands), 123456);
    }

    // compute GHASH using RustCrypto's ghash
    fn rust_crypto_ghash(h: u128, blocks: &Vec<u128>) -> u128 {
        let mut ghash = GHash::new(&h.to_be_bytes().into());
        for block in blocks.iter() {
            ghash.update(&block.to_be_bytes().into());
        }
        let b = ghash.finalize().into_bytes();
        u128::from_be_bytes(b.as_slice().try_into().unwrap())
    }

    // prepare the expected powers of h by recursively multiplying h to
    // itself
    fn compute_expected_powers(h: u128, max: u16) -> Vec<u128> {
        // prepare the expected powers of h by recursively multiplying h to
        // itself
        let mut powers: Vec<u128> = vec![0u128; (max + 1) as usize];
        powers[1] = h;
        let mut prev_power = h;
        for i in 2..((max + 1) as usize) {
            powers[i] = block_mult(prev_power, h);
            prev_power = powers[i];
        }
        powers
    }

    fn setup_find_sum() -> BTreeMap<u16, u128> {
        let summands_keys: Vec<u16> = vec![1, 3, 5, 6, 8, 9, 12, 15];
        let mut summands: BTreeMap<u16, u128> = BTreeMap::new();
        // assign any value > 0 to elements at keys corresponding to
        // summands_keys
        for v in summands_keys.iter() {
            summands.insert(*v, (12345 + *v) as u128);
        }
        summands
    }

    fn setup_square_all(keys: Vec<u16>) -> BTreeMap<u16, u128> {
        let mut powers: BTreeMap<u16, u128> = BTreeMap::new();
        // assign any value to elements at keys corresponding to
        // powers_keys
        for v in keys.iter() {
            powers.insert(*v, (12345 + *v) as u128);
        }
        powers
    }

    fn product_from_shares(x: u128, y: u128) -> u128 {
        // instantiate with empty values, we only need rng for this test
        let (masked_xtable, my_product_share) = masked_xtable(&mut thread_rng(), x);

        // the other party who has the y value will receive only 1 value (out of 2)
        // for each entry in maskedXTable via Oblivious Transfer depending on the
        // bits of y. We simulate that here:
        let mut his_product_share = 0u128;
        let bits = u8vec_to_boolvec(&y.to_be_bytes());
        for i in 0..128 {
            // the first element in xTable corresponds to the highest bit of y
            his_product_share ^= masked_xtable[i][bits[i] as usize];
        }
        my_product_share ^ his_product_share
    }
}
