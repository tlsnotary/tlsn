use mpc_circuits::{
    builder::CircuitBuilder, circuits::nbit_xor, Circuit, ValueType, AES_128_REVERSE,
};

/// TLS stage 6
///
/// Compute AES-CTR
///
/// Inputs:
///
///   0. N_CWK: 16-byte Notary share of client write-key
///   1. N_CIV: 4-byte Notary share of client IV
///   2. U_CWK: 16-byte User share of client write-key
///   3. U_CIV: 4-byte User share of client IV
///   4. U_MASK: 16-byte User mask for encrypted counter block
///   5. NONCE: U16 Nonce
///   6. CTR: U16 CTR
///
/// Outputs:
///
///   0. MASKED_ECTR: 16-byte masked (U_MASK) encrypted counter block
pub fn c6() -> Circuit {
    let mut builder = CircuitBuilder::new("c6", "0.1.0");

    let n_cwk = builder.add_input(
        "N_CWK",
        "16-byte Notary client write-key share",
        ValueType::Bytes,
        128,
    );
    let n_civ = builder.add_input(
        "N_SIV",
        "4-byte Notary share of client IV",
        ValueType::Bytes,
        32,
    );
    let u_cwk = builder.add_input(
        "U_SWK",
        "16-byte User share of client write-key",
        ValueType::Bytes,
        128,
    );
    let u_civ = builder.add_input(
        "U_SIV",
        "4-byte User share of client IV",
        ValueType::Bytes,
        32,
    );
    let u_mask = builder.add_input(
        "U_MASK",
        "16-byte User mask for encrypted counter block",
        ValueType::Bytes,
        128,
    );
    let nonce = builder.add_input("NONCE", "U64 Nonce", ValueType::U64, 64);
    let ctr = builder.add_input("CTR", "U32 CTR", ValueType::U32, 32);

    let mut builder = builder.build_inputs();

    let aes = Circuit::load_bytes(AES_128_REVERSE).expect("failed to load aes_128_reverse circuit");

    let aes_ectr = builder.add_circ(aes);
    let cwk = builder.add_circ(nbit_xor(128));
    let civ = builder.add_circ(nbit_xor(32));
    let masked_ectr = builder.add_circ(nbit_xor(128));

    // cwk
    builder.connect(
        &n_cwk[..],
        &cwk.input(0).expect("nbit_xor missing input 0")[..],
    );
    builder.connect(
        &u_cwk[..],
        &cwk.input(1).expect("nbit_xor missing input 1")[..],
    );
    let cwk = cwk.output(0).expect("nbit_xor missing output 0");

    // civ
    builder.connect(
        &n_civ[..],
        &civ.input(0).expect("nbit_xor missing input 0")[..],
    );
    builder.connect(
        &u_civ[..],
        &civ.input(1).expect("nbit_xor missing input 1")[..],
    );
    let civ = civ.output(0).expect("nbit_xor missing output 0");

    // Compute ECTR
    builder.connect(
        &cwk[..],
        &aes_ectr.input(0).expect("aes missing input 0")[..],
    );
    let aes_ectr_m = aes_ectr.input(1).expect("aes missing input 1");
    builder.connect(&civ[..], &aes_ectr_m[96..]);
    builder.connect(&nonce[..], &aes_ectr_m[32..96]);
    builder.connect(&ctr[..], &aes_ectr_m[..32]);
    let ectr = aes_ectr.output(0).expect("aes missing output 0");

    // Apply ECTR mask
    builder.connect(
        &ectr[..],
        &masked_ectr.input(0).expect("nbit_xor missing input 0")[..],
    );
    builder.connect(
        &u_mask[..],
        &masked_ectr.input(1).expect("nbit_xor missing input 1")[..],
    );

    let mut builder = builder.build_gates();

    let out_ectr = builder.add_output(
        "MASKED_ECTR",
        "16-byte masked (U_MASK) encrypted counter block",
        ValueType::Bytes,
        128,
    );

    builder.connect(
        &masked_ectr.output(0).expect("nbit_xor missing output 0")[..],
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

        let n_cwk: [u8; 16] = rng.gen();
        let n_civ: [u8; 4] = rng.gen();
        let u_cwk: [u8; 16] = rng.gen();
        let u_civ: [u8; 4] = rng.gen();
        let u_mask: [u8; 16] = rng.gen();
        let nonce: u64 = rng.gen();
        let ctr: u32 = rng.gen();

        // combine key shares
        let cwk = n_cwk
            .iter()
            .zip(u_cwk)
            .map(|(n, u)| n ^ u)
            .collect::<Vec<u8>>();
        let civ = n_civ
            .iter()
            .zip(u_civ)
            .map(|(n, u)| n ^ u)
            .collect::<Vec<u8>>();

        // set AES key
        let key = GenericArray::clone_from_slice(&cwk);
        let cipher = Aes128::new(&key);

        // AES-ECB encrypt a block with counter and nonce
        let mut msg = [0u8; 16];
        msg[0..4].copy_from_slice(&civ);
        msg[4..12].copy_from_slice(&nonce.to_be_bytes());
        msg[12..16].copy_from_slice(&ctr.to_be_bytes());
        let mut msg = GenericArray::clone_from_slice(&msg);
        cipher.encrypt_block(&mut msg);
        let ectr = msg;

        // XOR the first block and verify_data with User's mask
        let ectr_masked = ectr
            .iter()
            .zip(u_mask)
            .map(|(v, u)| v ^ u)
            .collect::<Vec<u8>>();

        test_circ(
            &circ,
            &[
                Value::Bytes(n_cwk.into_iter().rev().collect()),
                Value::Bytes(n_civ.into_iter().rev().collect()),
                Value::Bytes(u_cwk.into_iter().rev().collect()),
                Value::Bytes(u_civ.into_iter().rev().collect()),
                Value::Bytes(u_mask.into_iter().rev().collect()),
                Value::U64(nonce),
                Value::U32(ctr),
            ],
            &[Value::Bytes(ectr_masked.into_iter().rev().collect())],
        );
    }
}
