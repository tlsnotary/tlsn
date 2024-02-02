use crate::Delta;
use num::{BigInt, BigUint};
use sha2::{Digest, Sha256};

/// Converts bits in MSB-first order into a `BigUint`
pub fn bits_to_biguint(bits: &[bool]) -> BigUint {
    BigUint::from_bytes_be(&boolvec_to_u8vec(bits))
}
#[test]
fn test_bits_to_bigint() {
    let bits = [true, false];
    assert_eq!(bits_to_biguint(&bits), 2u8.into());
}

/// Converts bits in MSB-first order into BE bytes. The bits will be left-padded
/// with zeroes to the nearest multiple of 8.
pub fn boolvec_to_u8vec(bv: &[bool]) -> Vec<u8> {
    let rem = bv.len() % 8;
    let first_byte_bitsize = if rem == 0 { 8 } else { rem };
    let offset = if rem == 0 { 0 } else { 1 };
    let mut v = vec![0u8; bv.len() / 8 + offset];
    // implicitely left-pad the first byte with zeroes
    for (i, b) in bv[0..first_byte_bitsize].iter().enumerate() {
        v[i / 8] |= (*b as u8) << (first_byte_bitsize - 1 - i);
    }
    for (i, b) in bv[first_byte_bitsize..].iter().enumerate() {
        v[1 + i / 8] |= (*b as u8) << (7 - (i % 8));
    }
    v
}

/// Unzips a slice of pairs, returning items corresponding to choice
pub fn choose<T: Clone>(items: &[[T; 2]], choice: &[bool]) -> Vec<T> {
    assert!(items.len() == choice.len(), "arrays are different length");
    items
        .iter()
        .zip(choice)
        .map(|(items, choice)| items[*choice as usize].clone())
        .collect()
}

#[test]
fn test_boolvec_to_u8vec() {
    let bits = [true, false];
    assert_eq!(boolvec_to_u8vec(&bits), [2]);

    let bits = [true, false, false, false, false, false, false, true, true];
    assert_eq!(boolvec_to_u8vec(&bits), [1, 3]);
}

/// Converts BE bytes into bits in MSB-first order, left-padding with zeroes
/// to the nearest multiple of 8.
pub fn u8vec_to_boolvec(v: &[u8]) -> Vec<bool> {
    let mut bv = Vec::with_capacity(v.len() * 8);
    for byte in v.iter() {
        for i in 0..8 {
            bv.push(((byte >> (7 - i)) & 1) != 0);
        }
    }
    bv
}
#[test]
fn test_u8vec_to_boolvec() {
    let bytes = [1];
    assert_eq!(
        u8vec_to_boolvec(&bytes),
        [false, false, false, false, false, false, false, true]
    );

    let bytes = [255, 2];
    assert_eq!(
        u8vec_to_boolvec(&bytes),
        [
            true, true, true, true, true, true, true, true, false, false, false, false, false,
            false, true, false
        ]
    );

    // convert to bits and back to bytes
    let bignum: BigUint = 3898219876643u128.into();
    let bits = u8vec_to_boolvec(&bignum.to_bytes_be());
    let bytes = boolvec_to_u8vec(&bits);
    assert_eq!(bignum, BigUint::from_bytes_be(&bytes));
}

/// Returns sha256 hash digest
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Returns the sum of all zero labels and deltas for each label pair.
pub fn compute_zero_sum_and_deltas(
    arithmetic_label_pairs: &[[BigUint; 2]],
) -> (BigUint, Vec<Delta>) {
    let mut deltas: Vec<Delta> = Vec::with_capacity(arithmetic_label_pairs.len());
    let mut zero_sum: BigUint = 0u8.into();
    for label_pair in arithmetic_label_pairs {
        // calculate the sum of all zero labels
        zero_sum += label_pair[0].clone();
        // put deltas from into one vec
        deltas.push(BigInt::from(label_pair[1].clone()) - BigInt::from(label_pair[0].clone()));
    }
    (zero_sum, deltas)
}

#[test]
/// Tests compute_zero_sum_and_deltas()
fn test_compute_zero_sum_and_deltas() {
    let labels: [[BigUint; 2]; 2] = [[1u8.into(), 2u8.into()], [3u8.into(), 4u8.into()]];
    let (z, d) = compute_zero_sum_and_deltas(&labels);

    assert_eq!(z, 4u8.into());
    assert_eq!(d, [1u8.into(), 1u8.into()]);
}

/// Make sure that the `BigUint`s bitsize is not larger than `bitsize`
pub fn sanitize_biguint(input: &BigUint, bitsize: usize) -> Result<(), String> {
    if (input.bits() as usize) > bitsize {
        Err("error".to_string())
    } else {
        Ok(())
    }
}
#[test]
/// Tests sanitize_biguint()
fn test_sanitize_biguint() {
    let good = BigUint::from(2u8).pow(253) - BigUint::from(1u8);
    let res = sanitize_biguint(&good, 253);
    assert!(res.is_ok());

    let bad = BigUint::from(2u8).pow(253);
    let res = sanitize_biguint(&bad, 253);
    assert!(res.is_err());
}
