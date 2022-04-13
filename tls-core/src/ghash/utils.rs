use std::collections::BTreeMap;

// R is GCM polynomial in little-endian. In hex: "E1000000000000000000000000000000"
const R: u128 = 299076299051606071403356588563077529600;

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

// Also see comments to GhashReceiver::new

// We request OT for each share in each pair of the strategy, i.e. for
// shares: 4,1,4,3,8,1, etc. Even though it would be possible to introduce
// optimizations in order to avoid requesting OT for the same share more
// than once, that would only save us ~2000 OT instances at the cost of
// complicating the code.

pub static strategy1: BTreeMap<u8, [u8; 2]> = BTreeMap::from([
    (5, [4, 1]),
    (7, [4, 3]),
    (9, [8, 1]),
    (11, [8, 3]),
    (13, [12, 1]),
    (15, [12, 3]),
    (17, [16, 1]),
    (19, [16, 3]),
]);

pub static strategy2: BTreeMap<u8, [u8; 2]> = BTreeMap::from([
    (21, [17, 4]),
    (23, [17, 6]),
    (25, [17, 8]),
    (27, [19, 8]),
    (29, [17, 12]),
    (31, [19, 12]),
    (33, [17, 16]),
    (35, [19, 16]),
]);

pub static strategy11: [[u8; 3]; 8] = [
    [5, 4, 1],
    [7, 4, 3],
    [9, 8, 1],
    [11, 8, 3],
    [13, 12, 1],
    [15, 12, 3],
    [17, 16, 1],
    [19, 16, 3],
];
pub static strategy21: [[u8; 3]; 8] = [
    [21, 17, 4],
    [23, 17, 6],
    [25, 17, 8],
    [27, 19, 8],
    [29, 17, 12],
    [31, 19, 12],
    [33, 17, 16],
    [35, 19, 16],
];

// Galois field multiplication of two 128-bit blocks reduced by the GCM polynomial
pub fn block_mult(mut x: u128, y: u128) -> u128 {
    let mut result: u128 = 0;
    for i in (0..128).rev() {
        result ^= x * ((y >> i) & 1);
        x = (x >> 1) ^ ((x & 1) * R);
    }
    result
}

// free_square squares a value. It is called "free" because due to the
// property of Galois multiplication, squaring can be done locally without
// the need for 2PC.
pub fn free_square(x: u128) -> u128 {
    block_mult(x, x)
}

// square_all performs squaring of each odd power in "powers" up to and including
// the maximum power "max" and returns an updated map of powers. Squaring
// will be done recursively if needed, e.g if we have power == 1 and "max" is 22,
// then 1 will be squared to get power == 2, then 2 -> 4, 4 -> 8, 8 -> 16.
// Those powers which have already been squared will be skipped.
pub fn square_all(powers: &BTreeMap<u16, u128>, max: u16) -> BTreeMap<u16, u128> {
    let mut new_powers: BTreeMap<u16, u128> = BTreeMap::new();
    for (power, value) in powers.iter() {
        // The fact the we had earlier computed more powers that we will ever
        // need is a sign of error which needs to be investigated.
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

// find_sum finds 2 non-equal summands which add up to the needed sum. The
// first returned summand will be as small as possible.
// E.g if "summands" keys are 1,2,3,6 and "sum_needed" is 8, then
// the returned value would be (2,6).
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

// find_max_odd_power returns the maximum odd power that we'll need to compute
// GHASH in 2PC using Block Aggregation, where "max" is maximum power for GHASH
// (i.e it is the amount of GHASH blocks).
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
    for (key, value) in max_htable.iter() {
        if *value >= max {
            return *key;
        }
    }
    return 0;
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_find_max_odd_power() {
        assert_eq!(find_max_odd_power(1), 3);
        assert_eq!(find_max_odd_power(20), 5);
        assert_eq!(find_max_odd_power(100), 11);
        assert_eq!(find_max_odd_power(1000), 31);
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
}
