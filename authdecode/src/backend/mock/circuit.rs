use crate::{backend::mock::prover::hash, utils::boolvec_to_u8vec, Delta};
use num::{bigint::ToBigInt, BigInt, BigUint};

/// Checks in the clear that the given inputs satisfy all constraints of the AuthDecode circuit.
pub fn is_circuit_satisfied(
    plaintext_hash: BigUint,
    encoding_sum_hash: BigUint,
    zero_sum: BigUint,
    deltas: Vec<Delta>,
    plaintext: Vec<bool>,
    plaintext_salt: BigUint,
    encoding_sum_salt: BigUint,
) -> bool {
    assert!(plaintext.len() == deltas.len());
    // Compute dot product of plaintext and deltas.
    let dot_product = plaintext
        .iter()
        .zip(deltas.iter())
        .fold(BigInt::from(0u128), |acc, x| {
            let bit = if *(x.0) {
                BigInt::from(1u8)
            } else {
                BigInt::from(0u8)
            };
            let delta = x.1;
            acc + bit * delta
        });

    // Compute encoding sum, add salt, hash it and compare to the expected hash.
    // (Unwraps are safe since the encoding sum is non-negative by definition).
    let encoding_sum = (zero_sum.to_bigint().unwrap() + dot_product)
        .to_biguint()
        .unwrap();
    let mut encoding_sum = encoding_sum.to_bytes_be();
    encoding_sum.extend(encoding_sum_salt.to_bytes_be());
    let digest = BigUint::from_bytes_be(&hash(&encoding_sum));
    if digest != encoding_sum_hash {
        return false;
    }

    // Add salt to plaintext, hash it and compare to the expected hash.
    let mut plaintext = boolvec_to_u8vec(&plaintext);
    plaintext.extend(&plaintext_salt.to_bytes_be());
    let digest = BigUint::from_bytes_be(&hash(&plaintext));
    if digest != plaintext_hash {
        return false;
    }

    true
}
