use std::sync::Arc;

use mpc_circuits::{
    builder::CircuitBuilder, circuits::nbit_xor, Circuit, ValueType, AES_128_REVERSE,
};

/// AES encrypt counter-block and apply two additive masks
///
/// Inputs:
///
///   0. KEY: 16-byte encryption key
///   1. IV: 4-byte initialization-vector
///   2. NONCE: 8-byte Explicit Nonce
///   3. CTR: U32 Counter
///   4. MASK_0: 16-byte mask
///   5. MASK_1: 16-byte mask
///
/// Outputs:
///
///   0. T_OUT: 16-byte masked key block (C + MASK_0 + MASK_1)
pub fn aes_ctr_masked() -> Arc<Circuit> {
    let mut builder = CircuitBuilder::new("AESCTR", "AES-CTR encrypts a block of text", "0.1.0");

    let key = builder.add_input("KEY", "16-byte encryption key", ValueType::Bytes, 128);
    let iv = builder.add_input("IV", "4-byte initialization-vector", ValueType::Bytes, 32);
    let nonce = builder.add_input("NONCE", "8-byte Explicit Nonce", ValueType::Bytes, 64);
    let ctr = builder.add_input("CTR", "U32 Counter", ValueType::U32, 32);
    let mask_0 = builder.add_input("MASK_0", "16-byte mask", ValueType::Bytes, 128);
    let mask_1 = builder.add_input("MASK_1", "16-byte mask", ValueType::Bytes, 128);

    let mut builder = builder.build_inputs();

    let aes = Circuit::load_bytes(AES_128_REVERSE).expect("failed to load aes_128_reverse circuit");
    let xor_128_circ = nbit_xor(128);

    let aes_ectr = builder.add_circ(&aes);
    let xor_0 = builder.add_circ(&xor_128_circ);
    let xor_1 = builder.add_circ(&xor_128_circ);

    // Compute encrypted counter-block
    builder.connect(
        &key[..],
        &aes_ectr.input(0).expect("aes missing input 0")[..],
    );
    let aes_ectr_m = aes_ectr.input(1).expect("aes missing input 1");
    // Implicit nonce
    builder.connect(&iv[..], &aes_ectr_m[96..]);
    // Explicit nonce
    builder.connect(&nonce[..], &aes_ectr_m[32..96]);
    // Counter
    builder.connect(&ctr[..], &aes_ectr_m[..32]);
    let ectr = aes_ectr.output(0).expect("aes missing output 0");

    // Apply mask 0
    builder.connect(
        &ectr[..],
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

    let out_ectr = builder.add_output(
        "T_OUT",
        "16-byte masked key block (C + MASK_0 + MASK_1)",
        ValueType::Bytes,
        128,
    );

    builder.connect(
        &xor_1.output(0).expect("nbit_xor missing output 0")[..],
        &out_ectr[..],
    );

    builder
        .build_circuit()
        .expect("failed to build aes_ctr_masked")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::test_circ;
    use aes::Aes128;
    use cipher::{NewCipher, StreamCipher};
    use ctr::Ctr32BE;
    use mpc_circuits::Value;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    type Aes128Ctr = Ctr32BE<Aes128>;

    #[test]
    #[ignore = "expensive"]
    fn test_aes_ctr_masked() {
        let circ = aes_ctr_masked();

        let mut rng = ChaCha20Rng::seed_from_u64(0);

        let key: [u8; 16] = rng.gen();
        let iv: [u8; 4] = rng.gen();
        let explicit_nonce: [u8; 8] = rng.gen();
        let ctr = 1u32;
        let mask_0: [u8; 16] = rng.gen();
        let mask_1: [u8; 16] = rng.gen();

        let mut full_iv = [0u8; 16];
        full_iv[0..4].copy_from_slice(&iv);
        full_iv[4..12].copy_from_slice(&explicit_nonce);
        full_iv[15] = 1;
        let mut cipher = Aes128Ctr::new_from_slices(&key, &full_iv).unwrap();

        let mut encrypted_key_block = [0u8; 16];
        cipher.apply_keystream(&mut encrypted_key_block);

        let masked_encrypted_key_block = encrypted_key_block
            .iter()
            .zip(mask_0.iter())
            .zip(mask_1.iter())
            .map(|((a, b), c)| a ^ b ^ c)
            .collect::<Vec<_>>();

        test_circ(
            &circ,
            &[
                Value::Bytes(key.into_iter().rev().collect()),
                Value::Bytes(iv.into_iter().rev().collect()),
                Value::Bytes(explicit_nonce.into_iter().rev().collect()),
                Value::U32(ctr),
                Value::Bytes(mask_0.into_iter().rev().collect()),
                Value::Bytes(mask_1.into_iter().rev().collect()),
            ],
            &[Value::Bytes(
                masked_encrypted_key_block.into_iter().rev().collect(),
            )],
        );
    }
}
