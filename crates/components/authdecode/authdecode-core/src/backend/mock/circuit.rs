use crate::backend::{mock::prover::hash, traits::Field};
use itybity::ToBits;

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
    let dot_product = plaintext.to_lsb0_vec().into_iter().zip(deltas).fold(
        MockField::zero(),
        |acc, (bit, delta)| {
            let product = if bit { delta } else { MockField::zero() };
            acc + product
        },
    );

    // Compute encoding sum, add salt, hash it and compare to the expected hash.

    let encoding_sum = zero_sum + dot_product;
    let mut encoding_sum = encoding_sum.to_bytes();
    encoding_sum.extend(encoding_sum_salt.to_bytes());

    let digest = MockField::from_bytes(&hash(&encoding_sum));

    if digest != encoding_sum_hash {
        return false;
    }

    // Add salt to plaintext, hash it and compare to the expected hash.

    plaintext.extend(plaintext_salt.to_bytes());

    let digest = MockField::from_bytes(&hash(&plaintext));

    if digest != plaintext_hash {
        return false;
    }

    true
}
