use std::sync::Arc;

use mpc_circuits::{
    builder::CircuitBuilder, circuits::nbit_xor, Circuit, ValueType, AES_128_REVERSE,
};

/// Encrypt plaintext or decrypt ciphertext in AES-CTR mode
///
/// T_IN could also just be used as a mask for the encrypted counter-block.
///
/// Inputs:
///
///   0. KEY: 16-byte encryption key
///   1. IV: 4-byte initialization-vector
///   2. T_IN: 16-byte text (plaintext or ciphertext)
///   3. NONCE: 8-byte Explicit Nonce
///   4. CTR: U32 Counter
///
/// Outputs:
///
///   0. T_OUT: 16-byte output (plaintext or ciphertext)
pub fn aes_ctr() -> Arc<Circuit> {
    let mut builder = CircuitBuilder::new("AESCTR", "AES-CTR encrypts a block of text", "0.1.0");

    let key = builder.add_input("KEY", "16-byte encryption key", ValueType::Bytes, 128);
    let iv = builder.add_input("IV", "4-byte initialization-vector", ValueType::Bytes, 32);
    let t_in = builder.add_input(
        "T_IN",
        "16-byte text (plaintext or ciphertext)",
        ValueType::Bytes,
        128,
    );
    let nonce = builder.add_input("NONCE", "8-byte Explicit Nonce", ValueType::Bytes, 64);
    let ctr = builder.add_input("CTR", "U32 Counter", ValueType::U32, 32);

    let mut builder = builder.build_inputs();

    let aes = Circuit::load_bytes(AES_128_REVERSE).expect("failed to load aes_128_reverse circuit");
    let xor_128_circ = nbit_xor(128);

    let aes_ectr = builder.add_circ(&aes);
    let t_out = builder.add_circ(&xor_128_circ);

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

    // Apply text
    builder.connect(
        &ectr[..],
        &t_out.input(0).expect("nbit_xor missing input 0")[..],
    );
    builder.connect(
        &t_in[..],
        &t_out.input(1).expect("nbit_xor missing input 1")[..],
    );

    let mut builder = builder.build_gates();

    let out_ectr = builder.add_output(
        "T_OUT",
        "16-byte output (plaintext or ciphertext)",
        ValueType::Bytes,
        128,
    );

    builder.connect(
        &t_out.output(0).expect("nbit_xor missing output 0")[..],
        &out_ectr[..],
    );

    builder.build_circuit().expect("failed to build aes_ctr")
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
    fn test_aes_ctr() {
        let circ = aes_ctr();

        let mut rng = ChaCha20Rng::seed_from_u64(0);

        let key: [u8; 16] = rng.gen();
        let iv: [u8; 4] = rng.gen();
        let explicit_nonce: [u8; 8] = rng.gen();

        let mut full_iv = [0u8; 16];
        full_iv[0..4].copy_from_slice(&iv);
        full_iv[4..12].copy_from_slice(&explicit_nonce);
        full_iv[15] = 1;
        let mut cipher = Aes128Ctr::new_from_slices(&key, &full_iv).unwrap();

        for ctr in 1..9 {
            let msg: [u8; 16] = rng.gen();
            let mut expected = msg.to_vec();
            cipher.apply_keystream(&mut expected);

            test_circ(
                &circ,
                &[
                    Value::Bytes(key.into_iter().rev().collect()),
                    Value::Bytes(iv.into_iter().rev().collect()),
                    Value::Bytes(msg.into_iter().rev().collect()),
                    Value::Bytes(explicit_nonce.into_iter().rev().collect()),
                    Value::U32(ctr),
                ],
                &[Value::Bytes(expected.into_iter().rev().collect())],
            );
        }
    }
}
