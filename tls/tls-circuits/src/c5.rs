use std::sync::Arc;

use mpc_circuits::{
    builder::{map_le_bytes, CircuitBuilder},
    circuits::nbit_xor,
    Circuit, ValueType, AES_128_REVERSE, SHA_256,
};

/// TLS stage 5
///
/// Compute ghash H, gctr block, encrypted counter block, verify_data - needed for Server Finished
///
/// Inputs:
///
///   0. P1_OUTER_STATE: 32-byte outer hash state for P1
///   1. N_SWK: 16-byte Notary share of server write-key
///   2. N_SIV: 4-byte Notary share of server IV
///   3. N_H_MASK: 16-byte Notary mask for H
///   4. N_GCTR_MASK: 16-byte Notary mask for GCTR
///   5. P1_INNER_STATE: 32-byte inner hash for P1
///   6. U_SWK: 16-byte User share of server write-key
///   7. U_SIV: 4-byte User share of server IV
///   8. NONCE: 8-byte server_finished nonce
///   9. U_H_MASK: 16-byte User mask for H
///   10. U_GCTR_MASK: 16-byte User mask for GCTR
///   11. U_ECTR_MASK: 16-byte User mask for encrypted counter
///   12. U_VD_MASK: 12-byte User mask for server verify data
///
/// Outputs:
///
///   0. MASKED_H: 16-byte masked (N_H_MASK + U_H_MASK) H
///   1. MASKED_GCTR: 16-byte masked (N_GCTR_MASK + U_GCTR_MASK) GCTR
///   2. MASKED_ECTR: 16-byte masked (U_ECTR_MASK) encrypted counter
///   3. MASKED_VD: 12-byte masked (U_VD_MASK) server verify data
pub fn c5() -> Arc<Circuit> {
    let mut builder = CircuitBuilder::new("c5", "", "0.1.0");

    let p1_outer_state = builder.add_input(
        "P1_OUTER_STATE",
        "32-byte outer hash state for P1",
        ValueType::Bytes,
        256,
    );
    let n_swk = builder.add_input(
        "N_SWK",
        "16-byte Notary server write-key share",
        ValueType::Bytes,
        128,
    );
    let n_siv = builder.add_input(
        "N_SIV",
        "4-byte Notary share of server IV",
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
    let p1_inner_hash = builder.add_input(
        "P1_INNER_STATE",
        "32-byte inner hash for P1",
        ValueType::Bytes,
        256,
    );
    let u_swk = builder.add_input(
        "U_SWK",
        "16-byte User share of server write-key",
        ValueType::Bytes,
        128,
    );
    let u_siv = builder.add_input(
        "U_SIV",
        "4-byte User share of server IV",
        ValueType::Bytes,
        32,
    );
    let nonce = builder.add_input(
        "NONCE",
        "8-byte server_finished nonce",
        ValueType::Bytes,
        64,
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
    let u_vd_mask = builder.add_input(
        "U_VD_MASK",
        "12-byte User mask for server verify data",
        ValueType::Bytes,
        96,
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
    let sha256 = Circuit::load_bytes(SHA_256).expect("failed to load sha_256 circuit");
    let xor_128_circ = nbit_xor(128);
    let xor_96_circ = nbit_xor(96);
    let xor_32_circ = nbit_xor(32);

    let sha256_p1 = builder.add_circ(&sha256);
    let aes_h = builder.add_circ(&aes);
    let aes_gctr = builder.add_circ(&aes);
    let aes_ectr = builder.add_circ(&aes);
    let swk = builder.add_circ(&xor_128_circ);
    let siv = builder.add_circ(&xor_32_circ);
    let mask_h = builder.add_circ(&xor_128_circ);
    let mask_gctr = builder.add_circ(&xor_128_circ);
    let masked_h = builder.add_circ(&xor_128_circ);
    let masked_gctr = builder.add_circ(&xor_128_circ);
    let masked_ectr = builder.add_circ(&xor_128_circ);
    let masked_vd = builder.add_circ(&xor_96_circ);

    // swk
    builder.connect(
        &n_swk[..],
        &swk.input(0).expect("nbit_xor missing input 0")[..],
    );
    builder.connect(
        &u_swk[..],
        &swk.input(1).expect("nbit_xor missing input 1")[..],
    );
    let swk = swk.output(0).expect("nbit_xor missing output 0");

    // siv
    builder.connect(
        &n_siv[..],
        &siv.input(0).expect("nbit_xor missing input 0")[..],
    );
    builder.connect(
        &u_siv[..],
        &siv.input(1).expect("nbit_xor missing input 1")[..],
    );
    let siv = siv.output(0).expect("nbit_xor missing output 0");

    // Compute p1
    let sha256_p1_msg = sha256_p1.input(0).expect("sha256 missing input 0");
    builder.connect(&p1_inner_hash[..], &sha256_p1_msg[256..]);
    // append a single '1' bit
    builder.connect(&[const_one[0]], &[sha256_p1_msg[255]]);
    // append K '0' bits, where K is the minimum number >= 0 such that (L + 1 + K + 64) is a multiple of 512
    builder.connect(&[const_zero[0]; 239], &sha256_p1_msg[16..255]);
    // append L as a 64-bit big-endian integer, making the total post-processed length a multiple of 512 bits
    // L = 768 = 0x0300
    map_le_bytes(
        &mut builder,
        const_zero[0],
        const_one[0],
        &sha256_p1_msg[..16],
        &[0x00, 0x03],
    );
    builder.connect(
        &p1_outer_state[..],
        &sha256_p1.input(1).expect("sha256 missing input 1")[..],
    );
    let p1 = sha256_p1.output(0).expect("sha256 missing output 0");

    // Compute H
    builder.connect(&swk[..], &aes_h.input(0).expect("aes missing input 0")[..]);
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
        &swk[..],
        &aes_gctr.input(0).expect("aes missing input 0")[..],
    );
    let aes_gctr_m = aes_gctr.input(1).expect("aes missing input 1");
    builder.connect(&siv[..], &aes_gctr_m[96..]);
    builder.connect(&nonce[..], &aes_gctr_m[32..96]);
    // CTR (0x1)
    map_le_bytes(
        &mut builder,
        const_zero[0],
        const_one[0],
        &aes_gctr_m[..32],
        &[0x01, 0x00, 0x00, 0x00],
    );
    let gctr = aes_gctr.output(0).expect("aes missing output 0");

    // Compute ECTR
    builder.connect(
        &swk[..],
        &aes_ectr.input(0).expect("aes missing input 0")[..],
    );
    let aes_ectr_m = aes_ectr.input(1).expect("aes missing input 1");
    builder.connect(&siv[..], &aes_ectr_m[96..]);
    builder.connect(&nonce[..], &aes_ectr_m[32..96]);
    // CTR (0x2)
    map_le_bytes(
        &mut builder,
        const_zero[0],
        const_one[0],
        &aes_ectr_m[..32],
        &[0x02, 0x00, 0x00, 0x00],
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
        &masked_h.input(1).expect("nbit_xor missing input 1")[..],
    );

    // Apply GCTR mask
    builder.connect(
        &mask_gctr[..],
        &masked_gctr.input(0).expect("nbit_xor missing input 0")[..],
    );
    builder.connect(
        &gctr[..],
        &masked_gctr.input(1).expect("nbit_xor missing input 1")[..],
    );

    // Apply ECTR mask
    builder.connect(
        &ectr[..],
        &masked_ectr.input(0).expect("nbit_xor missing input 0")[..],
    );
    builder.connect(
        &u_ectr_mask[..],
        &masked_ectr.input(1).expect("nbit_xor missing input 1")[..],
    );

    // Apply VD mask
    builder.connect(
        &u_vd_mask[..],
        &masked_vd.input(0).expect("nbit_xor missing input 0")[..],
    );
    builder.connect(
        &p1[160..],
        &masked_vd.input(1).expect("nbit_xor missing input 1")[..],
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
    let out_vd = builder.add_output(
        "MASKED_VD",
        "12-byte masked (U_VD_MASK) server verify data",
        ValueType::Bytes,
        96,
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
    builder.connect(
        &masked_vd.output(0).expect("nbit_xor missing output 0")[..],
        &out_vd[..],
    );

    builder.build_circuit().expect("failed to build c5")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{finalize_sha256_digest, test_circ};
    use aes::{Aes128, BlockEncrypt, NewBlockCipher};
    use generic_array::GenericArray;
    use mpc_circuits::Value;
    use rand::{thread_rng, Rng};

    #[test]
    #[ignore = "expensive"]
    fn test_c5() {
        let circ = c5();

        let mut rng = thread_rng();

        let n_outer_hash_state_p1: [u32; 8] = rng.gen();
        let n_swk: [u8; 16] = rng.gen();
        let n_siv: [u8; 4] = rng.gen();
        let n_h_mask: [u8; 16] = rng.gen();
        let n_gctr_mask: [u8; 16] = rng.gen();
        let u_inner_hash_state_p1: [u8; 32] = rng.gen();
        let u_swk: [u8; 16] = rng.gen();
        let u_siv: [u8; 4] = rng.gen();
        let nonce: [u8; 8] = rng.gen();
        let u_h_mask: [u8; 16] = rng.gen();
        let u_gctr_mask: [u8; 16] = rng.gen();
        let u_ectr_mask: [u8; 16] = rng.gen();
        let u_vd_mask: [u8; 12] = rng.gen();

        // finalize the hash to get p1
        let p1 = finalize_sha256_digest(n_outer_hash_state_p1, 64, &u_inner_hash_state_p1);
        let mut verify_data = [0u8; 12];
        verify_data.copy_from_slice(&p1[0..12]);

        // combine key shares
        let swk = n_swk
            .iter()
            .zip(u_swk)
            .map(|(n, u)| n ^ u)
            .collect::<Vec<u8>>();
        let siv = n_siv
            .iter()
            .zip(u_siv)
            .map(|(n, u)| n ^ u)
            .collect::<Vec<u8>>();

        // set AES key
        let key = GenericArray::clone_from_slice(&swk);
        let cipher = Aes128::new(&key);

        // AES-ECB encrypt 0, get MAC key
        let mut z = GenericArray::clone_from_slice(&[0u8; 16]);
        cipher.encrypt_block(&mut z);
        let mac_key = z;

        // AES-ECB encrypt a block with counter==1 and nonce from Server_Finished, get GCTR block
        let counter: [u8; 4] = 1u32.to_be_bytes();
        let mut msg = [0u8; 16];
        msg[0..4].copy_from_slice(&siv);
        msg[4..12].copy_from_slice(&nonce);
        msg[12..16].copy_from_slice(&counter);
        let mut msg = GenericArray::clone_from_slice(&msg);
        cipher.encrypt_block(&mut msg);
        let gctr_block = msg;

        // AES-ECB encrypt a block with counter==2 and nonce from Server_Finished
        let counter: [u8; 4] = 2u32.to_be_bytes();
        let mut msg = [0u8; 16];
        msg[0..4].copy_from_slice(&siv);
        msg[4..12].copy_from_slice(&nonce);
        msg[12..16].copy_from_slice(&counter);
        let mut msg = GenericArray::clone_from_slice(&msg);
        cipher.encrypt_block(&mut msg);
        let ectr = msg;

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

        // XOR the first block and verify_data with User's mask
        let ectr_masked = ectr
            .iter()
            .zip(u_ectr_mask)
            .map(|(v, u)| v ^ u)
            .collect::<Vec<u8>>();
        let verify_data_masked = verify_data
            .iter()
            .zip(u_vd_mask)
            .map(|(v, u)| v ^ u)
            .collect::<Vec<u8>>();

        test_circ(
            &circ,
            &[
                Value::Bytes(
                    n_outer_hash_state_p1
                        .into_iter()
                        .rev()
                        .map(|v| v.to_le_bytes())
                        .flatten()
                        .collect::<Vec<u8>>(),
                ),
                Value::Bytes(n_swk.into_iter().rev().collect()),
                Value::Bytes(n_siv.into_iter().rev().collect()),
                Value::Bytes(n_h_mask.into_iter().rev().collect()),
                Value::Bytes(n_gctr_mask.into_iter().rev().collect()),
                Value::Bytes(u_inner_hash_state_p1.into_iter().rev().collect()),
                Value::Bytes(u_swk.into_iter().rev().collect()),
                Value::Bytes(u_siv.into_iter().rev().collect()),
                Value::Bytes(nonce.into_iter().rev().collect()),
                Value::Bytes(u_h_mask.into_iter().rev().collect()),
                Value::Bytes(u_gctr_mask.into_iter().rev().collect()),
                Value::Bytes(u_ectr_mask.into_iter().rev().collect()),
                Value::Bytes(u_vd_mask.into_iter().rev().collect()),
            ],
            &[
                Value::Bytes(mac_key_masked.into_iter().rev().collect()),
                Value::Bytes(gctr_block_masked.into_iter().rev().collect()),
                Value::Bytes(ectr_masked.into_iter().rev().collect()),
                Value::Bytes(verify_data_masked.into_iter().rev().collect()),
            ],
        );
    }
}
