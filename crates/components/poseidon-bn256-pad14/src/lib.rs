//! Poseidon hash over the bn256 curve with the input padding length of 14 field
//! elements.

use poseidon_circomlib::{hash as hash_inner, F};

/// Maximum allowed bytelength of plaintext.
const MAX_PLAINTEXT: usize = 434;
/// How many bytes to pack into a single field element.
const BYTES_PER_FIELD: usize = 31;
/// The length to pad the plaintext field element count to.  
const PAD_LENGTH: usize = 14;

/// Hashes the given `plaintext` (padding it) and `salt`, returning the digest
/// as bytes.
///
/// # Panics
///
/// Panics if the plaintext or salt lengths are not correct.
pub fn hash(plaintext: &[u8], salt: &[u8]) -> Vec<u8> {
    hash_to_field(plaintext, salt).to_bytes().to_vec()
}

/// Hashes the given `plaintext` (padding it) and `salt`, returning the digest
/// as a field element.
///
/// # Panics
///
/// Panics if the plaintext or salt lengths are not correct.
pub fn hash_to_field(plaintext: &[u8], salt: &[u8]) -> F {
    assert!(plaintext.len() <= MAX_PLAINTEXT);

    let mut plaintext: Vec<F> = plaintext
        .chunks(BYTES_PER_FIELD)
        .map(bytes_to_f)
        .collect::<Vec<_>>();

    // Zero-pad if needed.
    plaintext.extend(vec![F::zero(); PAD_LENGTH - plaintext.len()]);

    plaintext.push(bytes_to_f(salt));

    hash_inner(&plaintext)
}

/// Converts a little-endian byte representation of a scalar into a `F`.
fn bytes_to_f(bytes: &[u8]) -> F {
    assert!(bytes.len() <= BYTES_PER_FIELD);

    let mut raw = [0u8; 32];
    raw[0..bytes.len()].copy_from_slice(bytes);

    F::from_bytes(&raw).expect("Conversion should never fail")
}

#[cfg(test)]
mod test {
    // Tests that the digest equals that of the reference implementation.
    #[test]
    fn test_reference() {
        use super::*;
        use poseidon_circomlib::hash as reference_hash;

        let plaintext = 1u8;
        let salt = 2u8;

        let mut input: Vec<F> = Vec::with_capacity(15);
        input.push((plaintext as u64).into());
        input.extend(std::iter::repeat(F::zero()).take(13));
        input.push((salt as u64).into());

        let expected = reference_hash(&input);

        assert_eq!(expected.to_bytes().to_vec(), hash(&[plaintext], &[salt]));
    }
}
