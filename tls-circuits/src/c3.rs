use mpc_circuits::{
    builder::{map_le_bytes, CircuitBuilder},
    circuits::nbit_xor,
    Circuit, ValueType, SHA_256,
};

/// TLS stage 3
///
/// Compute expanded p1 which consists of client_write_key + server_write_key
/// Compute expanded p2 which consists of client_IV + server_IV
///
/// Inputs:
///
///   0. OUTER_HASH_STATE: 32-byte outer-hash state
///   1. N_CWK_MASK: 16-byte mask for client write-key
///   2. N_SWK_MASK: 16-byte mask for server write-key
///   3. N_CIV_MASK: 4-byte mask for client IV
///   4. N_SIV_MASK: 4-byte mask for server IV
///   5. P1_INNER: 32-byte inner hash for p1_expanded_keys
///   6. P2_INNER: 32-byte inner hash for p2_expanded_keys
///   7. U_CWK_MASK: 16-byte mask for client write-key
///   8. U_SWK_MASK: 16-byte mask for server write-key
///   9. U_CIV_MASK: 4-byte mask for client IV
///   10. U_SIV_MASK: 4-byte mask for server IV
///
/// Outputs:
///
///   0. MASKED_CWK: 16-byte masked (N_CWK_MASK + U_CWK_MASK) client write-key
///   1. MASKED_SWK: 16-byte masked (N_SWK_MASK + U_SWK_MASK) server write-key
///   2. MASKED_CIV: 4-byte masked (N_CIV_MASK + U_CIV_MASK) client IV
///   3. MASKED_SIV: 4-byte masked (N_SIV_MASK + U_SIV_MASK) server IV
pub fn c3() -> Circuit {
    let mut builder = CircuitBuilder::new("c3", "0.1.0");

    let outer_state = builder.add_input(
        "OUTER_HASH_STATE",
        "32-byte hash state",
        ValueType::Bytes,
        256,
    );
    let n_cwk_mask = builder.add_input(
        "N_CWK_MASK",
        "16-byte mask for client write-key",
        ValueType::Bytes,
        128,
    );
    let n_swk_mask = builder.add_input(
        "N_SWK_MASK",
        "16-byte mask for server write-key",
        ValueType::Bytes,
        128,
    );
    let n_civ_mask = builder.add_input(
        "N_CIV_MASK",
        "4-byte mask for client IV",
        ValueType::Bytes,
        32,
    );
    let n_siv_mask = builder.add_input(
        "N_SIV_MASK",
        "4-byte mask for server IV",
        ValueType::Bytes,
        32,
    );
    let p1_hash = builder.add_input(
        "P1_INNER",
        "32-byte inner hash for p1_expanded_keys",
        ValueType::Bytes,
        256,
    );
    let p2_hash = builder.add_input(
        "P2_INNER",
        "32-byte inner hash for p2_expanded_keys",
        ValueType::Bytes,
        256,
    );
    let u_cwk_mask = builder.add_input(
        "U_CWK_MASK",
        "16-byte mask for client write-key",
        ValueType::Bytes,
        128,
    );
    let u_swk_mask = builder.add_input(
        "U_SWK_MASK",
        "16-byte mask for server write-key",
        ValueType::Bytes,
        128,
    );
    let u_civ_mask = builder.add_input(
        "U_CIV_MASK",
        "4-byte mask for client IV",
        ValueType::Bytes,
        32,
    );
    let u_siv_mask = builder.add_input(
        "U_SIV_MASK",
        "4-byte mask for server IV",
        ValueType::Bytes,
        32,
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

    let sha256 = Circuit::load_bytes(SHA_256).expect("failed to load sha256 circuit");

    let sha256_p1 = builder.add_circ(sha256.clone());
    let sha256_p2 = builder.add_circ(sha256);
    let mask_cwk = builder.add_circ(nbit_xor(128));
    let mask_swk = builder.add_circ(nbit_xor(128));
    let mask_civ = builder.add_circ(nbit_xor(32));
    let mask_siv = builder.add_circ(nbit_xor(32));
    let masked_cwk = builder.add_circ(nbit_xor(128));
    let masked_swk = builder.add_circ(nbit_xor(128));
    let masked_civ = builder.add_circ(nbit_xor(32));
    let masked_siv = builder.add_circ(nbit_xor(32));

    // p1
    let sha256_p1_msg = sha256_p1.input(0).expect("sha256 missing input 0");
    builder.connect(&p1_hash[..], &sha256_p1_msg[256..]);
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
        &outer_state[..],
        &sha256_p1.input(1).expect("sha256 missing input 1")[..],
    );

    let p1 = sha256_p1.output(0).expect("sha256 missing output 0");

    // p2
    let sha256_p2_msg = sha256_p2.input(0).expect("sha256 missing input 0");
    builder.connect(&p2_hash[..], &sha256_p2_msg[256..]);
    // append a single '1' bit
    builder.connect(&[const_one[0]], &[sha256_p2_msg[255]]);
    // append K '0' bits, where K is the minimum number >= 0 such that (L + 1 + K + 64) is a multiple of 512
    builder.connect(&[const_zero[0]; 239], &sha256_p2_msg[16..255]);
    // append L as a 64-bit big-endian integer, making the total post-processed length a multiple of 512 bits
    // L = 768 = 0x0300
    map_le_bytes(
        &mut builder,
        const_zero[0],
        const_one[0],
        &sha256_p2_msg[..16],
        &[0x00, 0x03],
    );
    builder.connect(
        &outer_state[..],
        &sha256_p2.input(1).expect("sha256 missing input 1")[..],
    );

    let p2 = sha256_p2.output(0).expect("sha256 missing output 0");

    // cwk mask
    builder.connect(
        &n_cwk_mask[..],
        &mask_cwk.input(0).expect("nbit_xor missing input 0")[..],
    );
    builder.connect(
        &u_cwk_mask[..],
        &mask_cwk.input(1).expect("nbit_xor missing input 1")[..],
    );

    // swk mask
    builder.connect(
        &n_swk_mask[..],
        &mask_swk.input(0).expect("nbit_xor missing input 0")[..],
    );
    builder.connect(
        &u_swk_mask[..],
        &mask_swk.input(1).expect("nbit_xor missing input 1")[..],
    );

    // civ mask
    builder.connect(
        &n_civ_mask[..],
        &mask_civ.input(0).expect("nbit_xor missing input 0")[..],
    );
    builder.connect(
        &u_civ_mask[..],
        &mask_civ.input(1).expect("nbit_xor missing input 1")[..],
    );

    // siv mask
    builder.connect(
        &n_siv_mask[..],
        &mask_siv.input(0).expect("nbit_xor missing input 0")[..],
    );
    builder.connect(
        &u_siv_mask[..],
        &mask_siv.input(1).expect("nbit_xor missing input 1")[..],
    );

    // apply cwk mask
    builder.connect(
        &mask_cwk.output(0).expect("nbit_xor missing output 0")[..],
        &masked_cwk.input(0).expect("nbit_xor missing input 0")[..],
    );
    builder.connect(
        &p1[128..],
        &masked_cwk.input(1).expect("nbit_xor missing input 1")[..],
    );

    // apply swk mask
    builder.connect(
        &mask_swk.output(0).expect("nbit_xor missing output 0")[..],
        &masked_swk.input(0).expect("nbit_xor missing input 0")[..],
    );
    builder.connect(
        &p1[..128],
        &masked_swk.input(1).expect("nbit_xor missing input 1")[..],
    );

    // apply civ mask
    builder.connect(
        &mask_civ.output(0).expect("nbit_xor missing output 0")[..],
        &masked_civ.input(0).expect("nbit_xor missing input 1")[..],
    );
    builder.connect(
        &p2[224..],
        &masked_civ.input(1).expect("nbit_xor missing input 1")[..],
    );

    // apply siv mask
    builder.connect(
        &mask_siv.output(0).expect("nbit_xor missing output 0")[..],
        &masked_siv.input(0).expect("nbit_xor missing input 0")[..],
    );
    builder.connect(
        &p2[192..224],
        &masked_siv.input(1).expect("nbit_xor missing input 1")[..],
    );

    let mut builder = builder.build_gates();

    let cwk = builder.add_output(
        "MASKED_CWK",
        "16-byte masked client write-key",
        ValueType::Bytes,
        128,
    );
    let swk = builder.add_output(
        "MASKED_SWK",
        "16-byte masked server write-key",
        ValueType::Bytes,
        128,
    );
    let civ = builder.add_output(
        "MASKED_CIV",
        "4-byte masked client IV",
        ValueType::Bytes,
        32,
    );
    let siv = builder.add_output(
        "MASKED_SIV",
        "4-byte masked server IV",
        ValueType::Bytes,
        32,
    );

    builder.connect(
        &masked_cwk.output(0).expect("nbit_xor missing output 0")[..],
        &cwk[..],
    );
    builder.connect(
        &masked_swk.output(0).expect("nbit_xor missing output 0")[..],
        &swk[..],
    );
    builder.connect(
        &masked_civ.output(0).expect("nbit_xor missing output 0")[..],
        &civ[..],
    );
    builder.connect(
        &masked_siv.output(0).expect("nbit_xor missing output 0")[..],
        &siv[..],
    );

    builder.build_circuit().expect("failed to build c3")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{finalize_sha256_digest, test_circ};
    use mpc_circuits::Value;
    use rand::{thread_rng, Rng};

    #[test]
    #[ignore = "expensive"]
    fn test_c3() {
        let circ = c3();
        // Perform in the clear all the computations which happen inside the ciruit:
        let mut rng = thread_rng();

        let n_outer_hash_state: [u32; 8] = rng.gen();
        let n_cwk_mask: [u8; 16] = rng.gen();
        let n_swk_mask: [u8; 16] = rng.gen();
        let n_civ_mask: [u8; 4] = rng.gen();
        let n_siv_mask: [u8; 4] = rng.gen();
        let u_inner_hash_p1: [u8; 32] = rng.gen();
        let u_inner_hash_p2: [u8; 32] = rng.gen();
        let u_cwk_mask: [u8; 16] = rng.gen();
        let u_swk_mask: [u8; 16] = rng.gen();
        let u_civ_mask: [u8; 4] = rng.gen();
        let u_siv_mask: [u8; 4] = rng.gen();

        // finalize the hash to get p1
        let p1 = finalize_sha256_digest(n_outer_hash_state, 64, &u_inner_hash_p1);
        // finalize the hash to get p2
        let p2 = finalize_sha256_digest(n_outer_hash_state, 64, &u_inner_hash_p2);

        // get expanded_keys (TLS session keys)
        let mut ek = [0u8; 40];
        ek[..32].copy_from_slice(&p1);
        ek[32..40].copy_from_slice(&p2[0..8]);
        // split into client/server_write_key and client/server_write_iv
        let mut cwk = [0u8; 16];
        cwk.copy_from_slice(&ek[0..16]);
        let mut swk = [0u8; 16];
        swk.copy_from_slice(&ek[16..32]);
        let mut civ = [0u8; 4];
        civ.copy_from_slice(&ek[32..36]);
        let mut siv = [0u8; 4];
        siv.copy_from_slice(&ek[36..40]);

        let cwk_masked = cwk
            .iter()
            .zip(n_cwk_mask)
            .zip(u_cwk_mask)
            .map(|((v, n_mask), u_mask)| v ^ n_mask ^ u_mask)
            .collect::<Vec<u8>>();
        let swk_masked = swk
            .iter()
            .zip(n_swk_mask)
            .zip(u_swk_mask)
            .map(|((v, n_mask), u_mask)| v ^ n_mask ^ u_mask)
            .collect::<Vec<u8>>();
        let civ_masked = civ
            .iter()
            .zip(n_civ_mask)
            .zip(u_civ_mask)
            .map(|((v, n_mask), u_mask)| v ^ n_mask ^ u_mask)
            .collect::<Vec<u8>>();
        let siv_masked = siv
            .iter()
            .zip(n_siv_mask)
            .zip(u_siv_mask)
            .map(|((v, n_mask), u_mask)| v ^ n_mask ^ u_mask)
            .collect::<Vec<u8>>();

        test_circ(
            &circ,
            &[
                Value::Bytes(
                    n_outer_hash_state
                        .into_iter()
                        .rev()
                        .map(|v| v.to_le_bytes())
                        .flatten()
                        .collect::<Vec<u8>>(),
                ),
                Value::Bytes(n_cwk_mask.iter().rev().copied().collect::<Vec<u8>>()),
                Value::Bytes(n_swk_mask.iter().rev().copied().collect::<Vec<u8>>()),
                Value::Bytes(n_civ_mask.iter().rev().copied().collect::<Vec<u8>>()),
                Value::Bytes(n_siv_mask.iter().rev().copied().collect::<Vec<u8>>()),
                Value::Bytes(u_inner_hash_p1.into_iter().rev().collect()),
                Value::Bytes(u_inner_hash_p2.into_iter().rev().collect()),
                Value::Bytes(u_cwk_mask.iter().rev().copied().collect::<Vec<u8>>()),
                Value::Bytes(u_swk_mask.iter().rev().copied().collect::<Vec<u8>>()),
                Value::Bytes(u_civ_mask.iter().rev().copied().collect::<Vec<u8>>()),
                Value::Bytes(u_siv_mask.iter().rev().copied().collect::<Vec<u8>>()),
            ],
            &[
                Value::Bytes(cwk_masked.into_iter().rev().collect()),
                Value::Bytes(swk_masked.into_iter().rev().collect()),
                Value::Bytes(civ_masked.into_iter().rev().collect()),
                Value::Bytes(siv_masked.into_iter().rev().collect()),
            ],
        );
    }
}
