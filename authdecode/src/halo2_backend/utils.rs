use super::circuit::{CELLS_PER_ROW, USEFUL_ROWS};
use crate::{
    utils::{boolvec_to_u8vec, u8vec_to_boolvec},
    Delta,
};
use ff::{FromUniformBytes, PrimeField};
use halo2_proofs::halo2curves::bn256::Fr as F;
use num::BigUint;

/// Decomposes a `BigUint` into bits and returns the bits in MSB-first bit order,
/// left padding them with zeroes to the size of 256.
/// The assumption is that `bigint` was sanitized earlier and is not larger
/// than 256 bits
pub fn bigint_to_256bits(bigint: BigUint) -> [bool; 256] {
    let bits = u8vec_to_boolvec(&bigint.to_bytes_be());
    let mut bits256 = [false; 256];
    bits256[256 - bits.len()..].copy_from_slice(&bits);
    bits256
}
#[test]
fn test_bigint_to_256bits() {
    use num_bigint::RandomBits;
    use rand::{thread_rng, Rng};

    // test with a fixed number
    let res = bigint_to_256bits(BigUint::from(3u8));
    let expected: [bool; 256] = [vec![false; 254], vec![true; 2]]
        .concat()
        .try_into()
        .unwrap();
    assert_eq!(res, expected);

    // test with a random number
    let mut rng = thread_rng();
    let b: BigUint = rng.sample(RandomBits::new(256));
    let mut expected_bits: [bool; 256] = (0..256)
        .map(|i| b.bit(i))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    expected_bits.reverse();
    assert_eq!(bigint_to_256bits(b), expected_bits);
}

/// Converts a `BigUint` into an field element type.
/// The assumption is that `bigint` was sanitized earlier and is not larger
/// than [crate::verifier::Verify::field_size]
pub fn bigint_to_f(bigint: &BigUint) -> F {
    let le = bigint.to_bytes_le();
    let mut wide = [0u8; 64];
    wide[0..le.len()].copy_from_slice(&le);
    F::from_uniform_bytes(&wide)
}
#[test]
fn test_bigint_to_f() {
    // Test that the sum of 2 random `BigUint`s matches the sum of 2 field elements
    use num_bigint::RandomBits;
    use rand::{thread_rng, Rng};
    let mut rng = thread_rng();

    let a: BigUint = rng.sample(RandomBits::new(253));
    let b: BigUint = rng.sample(RandomBits::new(253));
    let c = a.clone() + b.clone();

    let a_f = bigint_to_f(&a);
    let b_f = bigint_to_f(&b);
    let c_f = a_f + b_f;

    assert_eq!(bigint_to_f(&c), c_f);
}

/// Converts `F` into a `BigUint` type.
/// The assumption is that the field is <= 256 bits
pub fn f_to_bigint(f: &F) -> BigUint {
    let tmp: [u8; 32] = f.try_into().unwrap();
    BigUint::from_bytes_le(&tmp)
}
#[test]
fn test_f_to_bigint() {
    // Test that the sum of 2 random `F`s matches the expected sum
    use rand::{thread_rng, Rng};
    let mut rng = thread_rng();

    let a = rng.gen::<u128>();
    let b = rng.gen::<u128>();

    let res = f_to_bigint(&(F::from_u128(a) + F::from_u128(b)));
    let expected: BigUint = BigUint::from(a) + BigUint::from(b);

    assert_eq!(res, expected);
}

/// Splits up 256 bits into 4 limbs, shifts each limb left
/// and returns the shifted limbs as `BigUint`s.
pub fn bits_to_limbs(bits: [bool; 256]) -> [BigUint; 4] {
    // break up the field element into 4 64-bit limbs
    // the limb at index 0 is the high limb
    let limbs: [BigUint; 4] = bits
        .chunks(64)
        .map(|c| BigUint::from_bytes_be(&boolvec_to_u8vec(c)))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    // shift each limb to the left:

    let two = BigUint::from(2u8);
    // how many bits to left-shift each limb by
    let shift_by: [BigUint; 4] = [192, 128, 64, 0]
        .iter()
        .map(|s| two.pow(*s))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    limbs
        .iter()
        .zip(shift_by.iter())
        .map(|(l, s)| l * s)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}
#[test]
fn test_bits_to_limbs() {
    use std::str::FromStr;

    let bits: [bool; 256] = [
        vec![false; 63],
        vec![true],
        vec![false; 63],
        vec![true],
        vec![false; 63],
        vec![true],
        vec![false; 63],
        vec![true],
    ]
    .concat()
    .try_into()
    .unwrap();
    let res = bits_to_limbs(bits);
    let expected = [
        BigUint::from_str("6277101735386680763835789423207666416102355444464034512896").unwrap(),
        BigUint::from_str("340282366920938463463374607431768211456").unwrap(),
        BigUint::from_str("18446744073709551616").unwrap(),
        BigUint::from_str("1").unwrap(),
    ];
    assert_eq!(res, expected);
}

/// Converts a vec of deltas into a matrix of rows and a matrix of
/// columns and returns them.
///
/// Assumes that the size of `deltas` is [super::CHUNK_SIZE]
pub fn deltas_to_matrices(
    deltas: &[Delta],
    useful_bits: usize,
) -> (
    [[F; CELLS_PER_ROW]; USEFUL_ROWS],
    [[F; USEFUL_ROWS]; CELLS_PER_ROW],
) {
    let deltas = convert_and_pad_deltas(deltas, useful_bits);
    let deltas_as_rows = deltas_to_matrix_of_rows(&deltas);

    let deltas_as_columns = transpose_rows(&deltas_as_rows);

    (deltas_as_rows, deltas_as_columns)
}
#[test]
fn test_deltas_to_matrices() {
    use super::CHUNK_SIZE;

    // all deltas except the penultimate one are 1. The penultimate delta is 2.
    let deltas = [
        vec![Delta::from(1u8); CHUNK_SIZE - 2],
        vec![BigUint::from(2u8)],
        vec![BigUint::from(1u8)],
    ]
    .concat();

    let (deltas_as_rows, deltas_as_columns) = deltas_to_matrices(&deltas, 253);
    let dar_concat = deltas_as_rows.concat();
    let dac_concat = deltas_as_columns.concat();

    // both matrices must contain equal amount of elements
    assert_eq!(dar_concat.len(), dac_concat.len());

    // 3 extra padding deltas were added 14 times
    assert_eq!(dar_concat.len(), deltas.len() + 14 * 3);

    // the penultimate element in the last row should be 2
    let row = deltas_as_rows[deltas_as_rows.len() - 1];
    assert_eq!(row[row.len() - 2], F::from(2));

    // the last element in the penultimate column should be 2
    let col = deltas_as_columns[deltas_as_columns.len() - 2];
    assert_eq!(col[col.len() - 1], F::from(2));
}

/// To make handling inside the circuit simpler, we pad each chunk (except for
/// the last one) of deltas with zero values on the left to the size 256.
/// Note that the last chunk (corresponding to the 15th field element) will
/// contain only 128 deltas, so we do NOT pad it.
///
/// Returns padded deltas
fn convert_and_pad_deltas(deltas: &[Delta], useful_bits: usize) -> Vec<F> {
    // convert deltas into F type
    let deltas: Vec<F> = deltas.iter().map(bigint_to_f).collect();

    deltas
        .chunks(useful_bits)
        .enumerate()
        .flat_map(|(i, c)| {
            if i < 14 {
                let mut v = vec![F::from(0); 256 - c.len()];
                v.extend(c.to_vec());
                v
            } else {
                c.to_vec()
            }
        })
        .collect()
}

/// Converts a vec of padded deltas into a matrix of rows and returns it.
fn deltas_to_matrix_of_rows(deltas: &[F]) -> [[F; CELLS_PER_ROW]; USEFUL_ROWS] {
    deltas
        .chunks(CELLS_PER_ROW)
        .map(|c| c.try_into().unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

/// Transposes a matrix of rows of fixed size.
fn transpose_rows(matrix: &[[F; CELLS_PER_ROW]; USEFUL_ROWS]) -> [[F; USEFUL_ROWS]; CELLS_PER_ROW] {
    (0..CELLS_PER_ROW)
        .map(|i| {
            matrix
                .iter()
                .map(|inner| inner[i])
                .collect::<Vec<_>>()
                .try_into()
                .unwrap()
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}
