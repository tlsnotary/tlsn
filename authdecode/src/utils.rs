use itybity::FromBitIterator;

/// Converts bits in MSB-first order into BE bytes. The bits will be internally left-padded
/// with zeroes to the nearest multiple of 8.
pub fn boolvec_to_u8vec(bv: &[bool]) -> Vec<u8> {
    let mut v = bv.to_vec();
    // Reverse to lsb0 since `itybity` can only pad the rightmost bits.
    v.reverse();
    let mut b = Vec::<u8>::from_lsb0_iter(v);
    // Reverse to get big endian byte order.
    b.reverse();
    b
}

/// Unzips a slice of pairs, returning items corresponding to choice.
pub fn choose<T: Clone>(items: &[[T; 2]], choice: &[bool]) -> Vec<T> {
    assert!(items.len() == choice.len(), "arrays are different length");
    items
        .iter()
        .zip(choice)
        .map(|(items, choice)| items[*choice as usize].clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boolvec_to_u8vec() {
        let bits = [true, false];
        assert_eq!(boolvec_to_u8vec(&bits), [2]);

        let bits = [true, false, false, false, false, false, false, true, true];
        assert_eq!(boolvec_to_u8vec(&bits), [1, 3]);
    }
}
