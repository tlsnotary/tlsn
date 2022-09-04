use mpc_circuits::{
    builder::{map_le_bytes, CircuitBuilder},
    circuits::nbit_xor,
    Circuit, ValueType, AES_128_REVERSE,
};

/// TLS stage 4
///
/// Compute ghash H, gctr block, encrypted counter block - needed for Client Finished
///
/// Inputs:
///
///   0. N_CWK: 16-byte Notary share of client write-key
///   1. N_CIV: 4-byte Notary share of client IV
///   2. N_H_MASK: 16-byte Notary mask for H
///   3. N_GCTR_MASK: 16-byte Notary mask for GCTR
///   4. U_CWK: 16-byte User share of client write-key
///   5. U_CIV: 4-byte User share of client IV
///   6. U_H_MASK: 16-byte User mask for H
///   7. U_GCTR_MASK: 16-byte User mask for GCTR
///   8. U_ECTR_MASK: 16-byte User mask for encrypted counter
///
/// Outputs:
///
///   0. MASKED_H: 16-byte masked (N_H_MASK + U_H_MASK) H
///   1. MASKED_GCTR: 16-byte masked (N_GCTR_MASK + U_GCTR_MASK) GCTR
///   2. MASKED_ECTR: 16-byte masked (U_ECTR_MASK) encrypted counter
pub fn c4() -> Circuit {
    let mut builder = CircuitBuilder::new("c4", "0.1.0");

    let n_cwk = builder.add_input(
        "N_CWK",
        "16-byte Notary share of client write-key",
        ValueType::Bytes,
        128,
    );
    let n_civ = builder.add_input(
        "N_CIV",
        "4-byte Notary share of client IV",
        ValueType::Bytes,
        32,
    );
    let n_h_mask = builder.add_input(
        "N_H_MASK",
        "16-byte Notary mask for H",
        ValueType::Bytes,
        128,
    );
    let n_gctr_mask = builder.add_input(
        "N_GCTR_MASK",
        "16-byte Notary mask for GCTR",
        ValueType::Bytes,
        128,
    );
    let u_cwk = builder.add_input(
        "U_CWK",
        "16-byte User share of client write-key",
        ValueType::Bytes,
        128,
    );
    let u_civ = builder.add_input(
        "U_CIV",
        "4-byte User share of client IV",
        ValueType::Bytes,
        32,
    );
    let u_h_mask = builder.add_input("U_H_MASK", "16-byte User mask for H", ValueType::Bytes, 128);
    let u_gctr_mask = builder.add_input(
        "U_GCTR_MASK",
        "16-byte User mask for GCTR",
        ValueType::Bytes,
        128,
    );
    let u_ectr_mask = builder.add_input(
        "U_ECTR_MASK",
        "16-byte User mask for ECTR",
        ValueType::Bytes,
        128,
    );
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

    let aes_h = builder.add_circ(aes.clone());
    let aes_gctr = builder.add_circ(aes.clone());
    let aes_ectr = builder.add_circ(aes);
    let cwk = builder.add_circ(nbit_xor(128));
    let civ = builder.add_circ(nbit_xor(32));
    let mask_h = builder.add_circ(nbit_xor(128));
    let mask_gctr = builder.add_circ(nbit_xor(128));
    let masked_h = builder.add_circ(nbit_xor(128));
    let masked_gctr = builder.add_circ(nbit_xor(128));
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

    // Compute H
    builder.connect(&cwk[..], &aes_h.input(0).expect("aes missing input 0")[..]);
    // encrypt all zeroes
    map_le_bytes(
        &mut builder,
        const_zero[0],
        const_one[0],
        &aes_h.input(1).expect("aes missing input 1")[..],
        &[0u8; 16],
    );
    let h = aes_h.output(0).expect("aes missing output 0");

    // Compute GCTR
    builder.connect(
        &cwk[..],
        &aes_gctr.input(0).expect("aes missing input 0")[..],
    );
    let aes_gctr_m = aes_gctr.input(1).expect("aes missing input 1");
    builder.connect(&civ[..], &aes_gctr_m[96..]);
    // Nonce (0x1) + CTR (0x1)
    map_le_bytes(
        &mut builder,
        const_zero[0],
        const_one[0],
        &aes_gctr_m[..96],
        &[
            0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
    );
    let gctr = aes_gctr.output(0).expect("aes missing output 0");

    // Compute ECTR
    builder.connect(
        &cwk[..],
        &aes_ectr.input(0).expect("aes missing input 0")[..],
    );
    let aes_ectr_m = aes_ectr.input(1).expect("aes missing input 1");
    builder.connect(&civ[..], &aes_ectr_m[96..]);
    // Nonce (0x1) + CTR (0x2)
    map_le_bytes(
        &mut builder,
        const_zero[0],
        const_one[0],
        &aes_ectr_m[..96],
        &[
            0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
    );
    let ectr = aes_ectr.output(0).expect("aes missing output 0");

    // H mask
    builder.connect(
        &n_h_mask[..],
        &mask_h.input(0).expect("nbit_xor missing input 0")[..],
    );
    builder.connect(
        &u_h_mask[..],
        &mask_h.input(1).expect("nbit_xor missing input 1")[..],
    );
    let mask_h = mask_h.output(0).expect("nbit_xor missing output 0");

    // GCTR mask
    builder.connect(
        &n_gctr_mask[..],
        &mask_gctr.input(0).expect("nbit_xor missing input 0")[..],
    );
    builder.connect(
        &u_gctr_mask[..],
        &mask_gctr.input(1).expect("nbit_xor missing input 1")[..],
    );
    let mask_gctr = mask_gctr.output(0).expect("nbit_xor missing output 0");

    // Apply H mask
    builder.connect(
        &mask_h[..],
        &masked_h.input(0).expect("nbit_xor missing input 0")[..],
    );
    builder.connect(
        &h[..],
        &masked_h.input(1).expect("nbit_xor missing input 0")[..],
    );

    // Apply GCTR mask
    builder.connect(
        &mask_gctr[..],
        &masked_gctr.input(0).expect("nbit_xor missing input 0")[..],
    );
    builder.connect(
        &gctr[..],
        &masked_gctr.input(1).expect("nbit_xor missing input 0")[..],
    );

    // Apply ECTR mask
    builder.connect(
        &ectr[..],
        &masked_ectr.input(0).expect("nbit_xor missing input 0")[..],
    );
    builder.connect(
        &u_ectr_mask[..],
        &masked_ectr.input(1).expect("nbit_xor missing input 0")[..],
    );

    let mut builder = builder.build_gates();

    let out_h = builder.add_output(
        "MASKED_H",
        "16-byte masked (N_H_MASK + U_H_MASK) H",
        ValueType::Bytes,
        128,
    );
    let out_gctr = builder.add_output(
        "MASKED_GCTR",
        "16-byte masked (N_GCTR_MASK + U_GCTR_MASK) GCTR",
        ValueType::Bytes,
        128,
    );
    let out_ectr = builder.add_output(
        "MASKED_ECTR",
        "16-byte masked (U_ECTR_MASK) encrypted counter",
        ValueType::Bytes,
        128,
    );

    builder.connect(
        &masked_h.output(0).expect("nbit_xor missing output 0")[..],
        &out_h[..],
    );
    builder.connect(
        &masked_gctr.output(0).expect("nbit_xor missing output 0")[..],
        &out_gctr[..],
    );
    builder.connect(
        &masked_ectr.output(0).expect("nbit_xor missing output 0")[..],
        &out_ectr[..],
    );

    builder.build_circuit().expect("failed to build c4")
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
    fn test_c4() {
        let circ = c4();

        let mut rng = thread_rng();

        let n_cwk: [u8; 16] = rng.gen();
        let n_civ: [u8; 4] = rng.gen();
        let n_h_mask: [u8; 16] = rng.gen();
        let n_gctr_mask: [u8; 16] = rng.gen();
        let u_cwk: [u8; 16] = rng.gen();
        let u_civ: [u8; 4] = rng.gen();
        let u_h_mask: [u8; 16] = rng.gen();
        let u_gctr_mask: [u8; 16] = rng.gen();
        let u_ectr_mask: [u8; 16] = rng.gen();

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
        let cipher = Aes128::new_from_slice(&cwk).unwrap();

        // AES-ECB encrypt 0, get MAC key
        let mut z = GenericArray::clone_from_slice(&[0u8; 16]);
        cipher.encrypt_block(&mut z);
        let mac_key = z;

        // AES-ECB encrypt a block with counter==1 and nonce==1, get GCTR block
        let nonce: [u8; 8] = 1u64.to_be_bytes();
        let counter: [u8; 4] = 1u32.to_be_bytes();
        let mut msg = [0u8; 16];
        msg[0..4].copy_from_slice(&civ);
        msg[4..12].copy_from_slice(&nonce);
        msg[12..16].copy_from_slice(&counter);
        let mut msg = GenericArray::clone_from_slice(&msg);
        cipher.encrypt_block(&mut msg);
        let gctr_block = msg;

        // AES-ECB encrypt a block with counter==2 and nonce==1
        let nonce: [u8; 8] = 1u64.to_be_bytes();
        let counter: [u8; 4] = 2u32.to_be_bytes();
        let mut msg = [0u8; 16];
        msg[0..4].copy_from_slice(&civ);
        msg[4..12].copy_from_slice(&nonce);
        msg[12..16].copy_from_slice(&counter);
        let mut msg = GenericArray::clone_from_slice(&msg);
        cipher.encrypt_block(&mut msg);
        let first_block = msg;

        // XOR MAC key and GCTR block with Notary's mask and then with User's mask
        let mac_key_masked = mac_key
            .iter()
            .zip(n_h_mask)
            .zip(u_h_mask)
            .map(|((v, n), u)| v ^ n ^ u)
            .collect::<Vec<u8>>();
        let gctr_block_masked = gctr_block
            .iter()
            .zip(n_gctr_mask)
            .zip(u_gctr_mask)
            .map(|((v, n), u)| v ^ n ^ u)
            .collect::<Vec<u8>>();

        // XOR the first block with User's mask
        let first_block_masked = first_block
            .iter()
            .zip(u_ectr_mask)
            .map(|(v, u)| v ^ u)
            .collect::<Vec<u8>>();

        test_circ(
            &circ,
            &[
                Value::Bytes(n_cwk.into_iter().rev().collect()),
                Value::Bytes(n_civ.into_iter().rev().collect()),
                Value::Bytes(n_h_mask.into_iter().rev().collect()),
                Value::Bytes(n_gctr_mask.into_iter().rev().collect()),
                Value::Bytes(u_cwk.into_iter().rev().collect()),
                Value::Bytes(u_civ.into_iter().rev().collect()),
                Value::Bytes(u_h_mask.into_iter().rev().collect()),
                Value::Bytes(u_gctr_mask.into_iter().rev().collect()),
                Value::Bytes(u_ectr_mask.into_iter().rev().collect()),
            ],
            &[
                Value::Bytes(mac_key_masked.into_iter().rev().collect()),
                Value::Bytes(gctr_block_masked.into_iter().rev().collect()),
                Value::Bytes(first_block_masked.into_iter().rev().collect()),
            ],
        );
    }
}
