use crate::{
    backend::{mock::prover::hash, traits::Field},
    utils::boolvec_to_u8vec,
};
use itybity::{FromBitIterator, IntoBits, StrToBits, ToBits};
use num::{
    bigint::{Sign, ToBigInt},
    BigInt, BigUint,
};

use super::MockField;

/// Checks in the clear that the given inputs satisfy all constraints of the AuthDecode circuit.
pub fn is_circuit_satisfied(
    plaintext_hash: MockField,
    encoding_sum_hash: MockField,
    zero_sum: MockField,
    deltas: Vec<MockField>,
    mut plaintext: Vec<u8>,
    plaintext_salt: MockField,
    encoding_sum_salt: MockField,
) -> bool {
    assert!(plaintext.len() * 8 == deltas.len());
    // Compute dot product of plaintext and deltas.
    let dot_product = plaintext.to_msb0_vec().into_iter().zip(deltas).fold(
        MockField::zero(),
        |acc, (bit, delta)| {
            let product = if bit { delta } else { MockField::zero() };
            acc + product
        },
    );

    // Compute encoding sum, add salt, hash it and compare to the expected hash.
    let encoding_sum = zero_sum + dot_product;
    let mut enc_sum = encoding_sum.to_bytes_be();
    enc_sum.extend(encoding_sum_salt.to_bytes_be());

    let hash_bytes = hash(&enc_sum);
    let digest = MockField::from_bytes_be(hash_bytes.to_vec());

    if digest != encoding_sum_hash {
        return false;
    }

    // Add salt to plaintext, hash it and compare to the expected hash.
    plaintext.extend(plaintext_salt.to_bytes_be());

    let hash_bytes = hash(&plaintext);
    let digest = MockField::from_bytes_be(hash_bytes.to_vec());

    if digest != plaintext_hash {
        return false;
    }

    true
}
