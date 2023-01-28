use std::sync::Arc;

use mpc_circuits::{
    builder::CircuitBuilder, circuits::nbit_xor, Circuit, ValueType, AES_128_REVERSE,
};

/// Encrypt plaintext and apply additive masks
///
/// Inputs:
///
///   0. KEY: 16-byte encryption key
///   1. TEXT: 16-byte plaintext
///   2. MASK_0: 16-byte additive mask
///   3. MASK_1: 16-byte additive mask
///
/// Outputs:
///
///   0. C_MASKED: 16-byte output (CIPHERTEXT + MASK_0 + MASK_1)
pub fn aes_masked() -> Arc<Circuit> {
    let mut builder = CircuitBuilder::new("AESCTR", "AES-CTR encrypts a block of text", "0.1.0");

    let key = builder.add_input("KEY", "16-byte encryption key", ValueType::Bytes, 128);
    let text = builder.add_input("TEXT", "16-byte plaintext", ValueType::Bytes, 128);
    let mask_0 = builder.add_input("MASK_0", "16-byte additive mask", ValueType::Bytes, 128);
    let mask_1 = builder.add_input("MASK_1", "16-byte additive mask", ValueType::Bytes, 128);

    let mut builder = builder.build_inputs();

    let aes_circ =
        Circuit::load_bytes(AES_128_REVERSE).expect("failed to load aes_128_reverse circuit");
    let xor_128_circ = nbit_xor(128);

    let aes = builder.add_circ(&aes_circ);
    let xor_0 = builder.add_circ(&xor_128_circ);
    let xor_1 = builder.add_circ(&xor_128_circ);

    // Compute ciphertext
    builder.connect(&key[..], &aes.input(0).expect("aes missing input 0")[..]);
    builder.connect(&text[..], &aes.input(1).expect("aes missing input 1")[..]);
    let ciphertext = aes.output(0).expect("aes missing output 0");

    // Apply mask_0
    builder.connect(
        &ciphertext[..],
        &xor_0.input(0).expect("nbit_xor missing input 0")[..],
    );
    builder.connect(
        &mask_0[..],
        &xor_0.input(1).expect("nbit_xor missing input 1")[..],
    );

    // Apply mask 1
    builder.connect(
        &xor_0.output(0).expect("nbit_xor missing output 0")[..],
        &xor_1.input(0).expect("nbit_xor missing input 0")[..],
    );
    builder.connect(
        &mask_1[..],
        &xor_1.input(1).expect("nbit_xor missing input 1")[..],
    );

    let mut builder = builder.build_gates();

    let ciphertext_masked = builder.add_output(
        "C_MASKED",
        "16-byte output (CIPHERTEXT + MASK_0 + MASK_1)",
        ValueType::Bytes,
        128,
    );

    builder.connect(
        &xor_1.output(0).expect("nbit_xor missing output 0")[..],
        &ciphertext_masked[..],
    );

    builder.build_circuit().expect("failed to build aes_masked")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::test_circ;
    use aes::{Aes128, BlockEncrypt, NewBlockCipher};
    use mpc_circuits::Value;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    #[ignore = "expensive"]
    fn test_aes_masked() {
        let circ = aes_masked();

        let mut rng = ChaCha20Rng::seed_from_u64(0);

        let key: [u8; 16] = rng.gen();
        let plaintext: [u8; 16] = rng.gen();
        let mask_0: [u8; 16] = rng.gen();
        let mask_1: [u8; 16] = rng.gen();

        let cipher = Aes128::new_from_slice(&key).unwrap();
        let mut ciphertext = plaintext.into();
        cipher.encrypt_block(&mut ciphertext);

        let mut ciphertext_masked = ciphertext
            .iter()
            .zip(mask_0.iter())
            .zip(mask_1.iter())
            .map(|((&a, &b), &c)| a ^ b ^ c)
            .collect::<Vec<_>>();

        test_circ(
            &circ,
            &[
                Value::Bytes(key.into_iter().rev().collect()),
                Value::Bytes(plaintext.into_iter().rev().collect()),
                Value::Bytes(mask_0.into_iter().rev().collect()),
                Value::Bytes(mask_1.into_iter().rev().collect()),
            ],
            &[Value::Bytes(ciphertext_masked.into_iter().rev().collect())],
        );
    }
}
