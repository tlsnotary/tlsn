use mpc_circuits::{
    builder::{map_le_bytes, CircuitBuilder},
    circuits::nbit_xor,
    Circuit, ValueType, AES_128_REVERSE,
};

/// TLS stage 7
///
/// Compute GCTR block
///
/// Inputs:
///
///   0. N_CWK: 16-byte Notary share of client write-key
///   1. N_CIV: 4-byte Notary share of client IV
///   2. N_MASK: 16-byte User mask for GCTR
///   3. U_CWK: 16-byte User share of client write-key
///   4. U_CIV: 4-byte User share of client IV
///   5. U_MASK: 16-byte User mask for GCTR
///   6. NONCE: U16 Nonce
///
/// Outputs:
///
///   0. MASKED_GCTR: 16-byte masked (N_MASK + U_MASK) GCTR
pub fn c7() -> Circuit {
    let mut builder = CircuitBuilder::new("c7", "0.1.0");

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
    let n_mask = builder.add_input(
        "N_MASK",
        "16-byte Notary mask for GCTR",
        ValueType::Bytes,
        128,
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
        "16-byte User mask for GCTR",
        ValueType::Bytes,
        128,
    );
    let nonce = builder.add_input("NONCE", "U64 Nonce", ValueType::U64, 64);
    let const_zero = builder.add_input(
        "const_zero",
        "input that is always 0",
        ValueType::ConstZero,
        1,
    );
    let const_one = builder.add_input(
        "const_one",
        "input that is always 1",
        ValueType::ConstOne,
        1,
    );

    let mut builder = builder.build_inputs();

    let aes = Circuit::load_bytes(AES_128_REVERSE).expect("failed to load aes_128_reverse circuit");

    let aes_gctr = builder.add_circ(aes);
    let cwk = builder.add_circ(nbit_xor(128));
    let civ = builder.add_circ(nbit_xor(32));
    let mask_gctr = builder.add_circ(nbit_xor(128));
    let masked_gctr = builder.add_circ(nbit_xor(128));

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

    // Compute GCTR
    builder.connect(
        &cwk[..],
        &aes_gctr.input(0).expect("aes missing input 0")[..],
    );
    let aes_gctr_m = aes_gctr.input(1).expect("aes missing input 1");
    builder.connect(&civ[..], &aes_gctr_m[96..]);
    builder.connect(&nonce[..], &aes_gctr_m[32..96]);
    map_le_bytes(
        &mut builder,
        const_zero[0],
        const_one[0],
        &aes_gctr_m[..32],
        &[0x01, 0x00, 0x00, 0x00],
    );
    let gctr = aes_gctr.output(0).expect("aes missing output 0");

    // GCTR mask
    builder.connect(
        &n_mask[..],
        &mask_gctr.input(0).expect("nbit_xor missing input 0")[..],
    );
    builder.connect(
        &u_mask[..],
        &mask_gctr.input(1).expect("nbit_xor missing input 1")[..],
    );
    let mask_gctr = mask_gctr.output(0).expect("nbit_xor missing output 0");

    // Apply GCTR mask
    builder.connect(
        &gctr[..],
        &masked_gctr.input(0).expect("nbit_xor missing input 0")[..],
    );
    builder.connect(
        &mask_gctr[..],
        &masked_gctr.input(1).expect("nbit_xor missing input 1")[..],
    );

    let mut builder = builder.build_gates();

    let out_gctr = builder.add_output(
        "MASKED_GCTR",
        "16-byte masked (N_MASK + U_MASK) GCTR",
        ValueType::Bytes,
        128,
    );

    builder.connect(
        &masked_gctr.output(0).expect("nbit_xor missing output 0")[..],
        &out_gctr[..],
    );

    builder.build_circuit().expect("failed to build c7")
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
    fn test_c7() {
        let circ = c7();

        let mut rng = thread_rng();

        let n_cwk: [u8; 16] = rng.gen();
        let n_civ: [u8; 4] = rng.gen();
        let n_mask: [u8; 16] = rng.gen();
        let u_cwk: [u8; 16] = rng.gen();
        let u_civ: [u8; 4] = rng.gen();
        let u_mask: [u8; 16] = rng.gen();
        let nonce: u64 = rng.gen();

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
        msg[12..16].copy_from_slice(&1u32.to_be_bytes());
        let mut msg = GenericArray::clone_from_slice(&msg);
        cipher.encrypt_block(&mut msg);
        let gctr = msg;

        // XOR the first block and verify_data with User's mask
        let gctr_masked = gctr
            .iter()
            .zip(n_mask)
            .zip(u_mask)
            .map(|((v, n), u)| v ^ n ^ u)
            .collect::<Vec<u8>>();

        test_circ(
            &circ,
            &[
                Value::Bytes(n_cwk.into_iter().rev().collect()),
                Value::Bytes(n_civ.into_iter().rev().collect()),
                Value::Bytes(n_mask.into_iter().rev().collect()),
                Value::Bytes(u_cwk.into_iter().rev().collect()),
                Value::Bytes(u_civ.into_iter().rev().collect()),
                Value::Bytes(u_mask.into_iter().rev().collect()),
                Value::U64(nonce),
            ],
            &[Value::Bytes(gctr_masked.into_iter().rev().collect())],
        );
    }
}
