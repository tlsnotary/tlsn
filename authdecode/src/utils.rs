/// Converts bits in MSB-first order into BE bytes. The bits will be internally left-padded
/// with zeroes to the nearest multiple of 8.
pub fn boolvec_to_u8vec(bv: &[bool]) -> Vec<u8> {
    let rem = bv.len() % 8;
    let first_byte_bitsize = if rem == 0 { 8 } else { rem };
    let offset = if rem == 0 { 0 } else { 1 };
    let mut v = vec![0u8; bv.len() / 8 + offset];

    // Implicitly left-pad the first byte with zeroes.
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

/// Converts BE bytes into bits in MSB-first order without padding,
pub fn u8vec_to_boolvec_no_pad(v: &[u8]) -> Vec<bool> {
    let mut padded = u8vec_to_boolvec(v);
    while !padded.is_empty() {
        if !padded.first().unwrap() {
            // Remove the leading zero.
            padded.remove(0);
        } else {
            break;
        }
    }

    if padded.is_empty() {
        // The input was zero.
        return vec![false];
    }
    padded
}

#[cfg(test)]
mod tests {
    use super::*;
    use num::BigUint;

    #[test]
    fn test_boolvec_to_u8vec() {
        let bits = [true, false];
        assert_eq!(boolvec_to_u8vec(&bits), [2]);

        let bits = [true, false, false, false, false, false, false, true, true];
        assert_eq!(boolvec_to_u8vec(&bits), [1, 3]);
    }

    #[test]
    fn test_u8vec_to_boolvec() {
        let bytes = [1];
        let mut bits = vec![false; 7];
        bits.extend(vec![true]);

        assert_eq!(u8vec_to_boolvec(&bytes), bits);

        let bytes = [255, 2];
        let mut bits = vec![true; 8];
        bits.extend(vec![false; 6]);
        bits.extend(vec![true, false]);

        assert_eq!(u8vec_to_boolvec(&bytes), bits);

        // Convert to bits and back to bytes.
        let bignum: BigUint = 3898219876643u128.into();
        let bits = u8vec_to_boolvec(&bignum.to_bytes_be());
        let bytes = boolvec_to_u8vec(&bits);

        assert_eq!(bignum, BigUint::from_bytes_be(&bytes));
    }
}
