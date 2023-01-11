use std::sync::Arc;

use mpc_circuits::{
    builder::CircuitBuilder, circuits::nbit_xor, Circuit, ValueType, AES_128_REVERSE,
};

/// TLS stage 6
///
/// Encrypt plaintext or decrypt ciphertext in AES-CTR mode
///
/// T_IN could also just be used as a mask for the encrypted counter-block.
///
/// Inputs:
///
///   0. N_K: 16-byte Notary share of write-key
///   1. N_IV: 4-byte Notary share of IV
///   2. U_K: 16-byte User share of write-key
///   3. U_IV: 4-byte User share of IV
///   4. T_IN: 16-byte text (plaintext or ciphertext)
///   5. NONCE: 8-byte Explicit Nonce
///   6. CTR: U32 Counter
///
/// Outputs:
///
///   0. T_OUT: 16-byte output (plaintext or ciphertext)
pub fn c6() -> Arc<Circuit> {
    let mut builder = CircuitBuilder::new("c6", "", "0.1.0");

    let n_k = builder.add_input(
        "N_K",
        "16-byte Notary write-key share",
        ValueType::Bytes,
        128,
    );
    let n_iv = builder.add_input("N_SIV", "4-byte Notary share of IV", ValueType::Bytes, 32);
    let c_k = builder.add_input(
        "U_SWK",
        "16-byte User share of write-key",
        ValueType::Bytes,
        128,
    );
    let c_iv = builder.add_input("U_SIV", "4-byte User share of IV", ValueType::Bytes, 32);
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
    let xor_32_circ = nbit_xor(32);

    let aes_ectr = builder.add_circ(&aes);
    let k = builder.add_circ(&xor_128_circ);
    let iv = builder.add_circ(&xor_32_circ);
    let t_out = builder.add_circ(&xor_128_circ);

    // Compute write-key
    builder.connect(&n_k[..], &k.input(0).expect("nbit_xor missing input 0")[..]);
    builder.connect(&c_k[..], &k.input(1).expect("nbit_xor missing input 1")[..]);
    let k = k.output(0).expect("nbit_xor missing output 0");

    // iv
    builder.connect(
        &n_iv[..],
        &iv.input(0).expect("nbit_xor missing input 0")[..],
    );
    builder.connect(
        &c_iv[..],
        &iv.input(1).expect("nbit_xor missing input 1")[..],
    );
    let iv = iv.output(0).expect("nbit_xor missing output 0");

    // Compute encrypted counter-block
    builder.connect(&k[..], &aes_ectr.input(0).expect("aes missing input 0")[..]);
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

    builder.build_circuit().expect("failed to build c6")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::test_circ;
    use aes::{Aes128, BlockEncrypt, NewBlockCipher};
    use generic_array::GenericArray;
    use mpc_circuits::Value;
    use rand::{thread_rng, Rng};

    #[test]
    #[ignore = "expensive"]
    fn test_c6() {
        let circ = c6();

        let mut rng = thread_rng();

        let n_k: [u8; 16] = rng.gen();
        let n_iv: [u8; 4] = rng.gen();
        let u_k: [u8; 16] = rng.gen();
        let u_iv: [u8; 4] = rng.gen();
        let t_in: [u8; 16] = rng.gen();
        let explicit_nonce: [u8; 8] = rng.gen();
        let ctr: u32 = rng.gen();

        // combine key shares
        let k = n_k.iter().zip(u_k).map(|(n, u)| n ^ u).collect::<Vec<u8>>();
        let iv = n_iv
            .iter()
            .zip(u_iv)
            .map(|(n, u)| n ^ u)
            .collect::<Vec<u8>>();

        // set AES key
        let key = GenericArray::clone_from_slice(&k);
        let cipher = Aes128::new(&key);

        // AES-ECB encrypt a block with counter and nonce
        let mut msg = [0u8; 16];
        msg[0..4].copy_from_slice(&iv);
        msg[4..12].copy_from_slice(&explicit_nonce);
        msg[12..16].copy_from_slice(&ctr.to_be_bytes());
        let mut msg = GenericArray::clone_from_slice(&msg);
        cipher.encrypt_block(&mut msg);
        let ectr = msg;

        let t_out = ectr
            .iter()
            .zip(t_in)
            .map(|(v, u)| v ^ u)
            .collect::<Vec<u8>>();

        test_circ(
            &circ,
            &[
                Value::Bytes(n_k.into_iter().rev().collect()),
                Value::Bytes(n_iv.into_iter().rev().collect()),
                Value::Bytes(u_k.into_iter().rev().collect()),
                Value::Bytes(u_iv.into_iter().rev().collect()),
                Value::Bytes(t_in.into_iter().rev().collect()),
                Value::Bytes(explicit_nonce.into_iter().rev().collect()),
                Value::U32(ctr),
            ],
            &[Value::Bytes(t_out.into_iter().rev().collect())],
        );
    }
}
