use crate::SHA256_STATE;
use mpc_circuits::{
    builder::{map_le_bytes, CircuitBuilder},
    circuits::nbit_xor,
    Circuit, ValueType, SHA_256,
};

/// TLS stage 2
///
/// Computes the master secret (MS).
/// Outputs sha256(ms xor opad) called "ms outer hash state" and
/// sha256(ms xor ipad) called "ms inner hash state"
///
/// Inputs:
///
///   0. PMS_O_STATE: 32-byte PMS outer-hash state
///   1. P1_INNER: 32-byte inner hash of P1
///   2. P2: 16-byte P2
///   3. MASK_I: 32-byte mask for inner-state
///   4. MASK_O: 32-byte mask for outer-state
///
/// Outputs:
///
///   0. MASKED_I: 32-byte masked HMAC inner hash state
///   1. MASKED_O: 32-byte masked HMAC outer hash state
pub fn c2() -> Circuit {
    let mut builder = CircuitBuilder::new("c2", "0.1.0");

    let pms_o = builder.add_input("PMS_O_STATE", "32-byte hash state", ValueType::Bytes, 256);
    let p1_inner = builder.add_input("P1_INNER", "32-byte hash state", ValueType::Bytes, 256);
    let p2 = builder.add_input("P2", "16-byte P2", ValueType::Bytes, 128);
    let mask_inner = builder.add_input(
        "MASK_I",
        "32-byte mask for inner-state",
        ValueType::Bytes,
        256,
    );
    let mask_outer = builder.add_input(
        "MASK_O",
        "32-byte mask for outer-state",
        ValueType::Bytes,
        256,
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
    let sha256_ipad = builder.add_circ(sha256.clone());
    let sha256_opad = builder.add_circ(sha256);
    let ms_ipad = builder.add_circ(nbit_xor(512));
    let ms_opad = builder.add_circ(nbit_xor(512));
    let masked_inner = builder.add_circ(nbit_xor(256));
    let masked_outer = builder.add_circ(nbit_xor(256));

    // p1
    let sha256_p1_msg = sha256_p1.input(0).expect("sha256 missing input 1");
    builder.connect(&p1_inner[..], &sha256_p1_msg[256..]);
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
        &pms_o[..],
        &sha256_p1.input(1).expect("sha256 missing input 1")[..],
    );

    let p1 = sha256_p1.output(0).expect("sha256 missing output 0");

    // inner
    map_le_bytes(
        &mut builder,
        const_zero[0],
        const_one[0],
        &ms_ipad.input(0).expect("nbit_xor missing input 0")[..],
        &[0x36u8; 64],
    );
    builder.connect(
        &p1[..],
        &ms_ipad.input(1).expect("nbit_xor missing input 1")[256..],
    );
    builder.connect(
        &p2[..],
        &ms_ipad.input(1).expect("nbit_xor missing input 1")[128..256],
    );
    builder.connect(
        &[const_zero[0]; 128],
        &ms_ipad.input(1).expect("nbit_xor missing input 1")[..128],
    );
    builder.connect(
        &ms_ipad.output(0).expect("nbit_xor missing output 0")[..],
        &sha256_ipad.input(0).expect("sha256 missing input 0")[..],
    );
    // map SHA256 initial state
    map_le_bytes(
        &mut builder,
        const_zero[0],
        const_one[0],
        &sha256_ipad.input(1).expect("sha256 missing input 1")[..],
        &SHA256_STATE
            .iter()
            .rev()
            .map(|chunk| chunk.to_le_bytes())
            .flatten()
            .collect::<Vec<u8>>(),
    );

    // outer
    map_le_bytes(
        &mut builder,
        const_zero[0],
        const_one[0],
        &ms_opad.input(0).expect("nbit_xor missing input 0")[..],
        &[0x5cu8; 64],
    );
    builder.connect(
        &p1[..],
        &ms_opad.input(1).expect("nbit_xor missing input 1")[256..],
    );
    builder.connect(
        &p2[..],
        &ms_opad.input(1).expect("nbit_xor missing input 1")[128..256],
    );
    builder.connect(
        &[const_zero[0]; 128],
        &ms_opad.input(1).expect("nbit_xor missing input 1")[..128],
    );
    builder.connect(
        &ms_opad.output(0).expect("nbit_xor missing output 0")[..],
        &sha256_opad.input(0).expect("sha256 missing input 0")[..],
    );
    // map SHA256 initial state
    map_le_bytes(
        &mut builder,
        const_zero[0],
        const_one[0],
        &sha256_opad.input(1).expect("sha256 missing input 1")[..],
        &SHA256_STATE
            .iter()
            .rev()
            .map(|chunk| chunk.to_le_bytes())
            .flatten()
            .collect::<Vec<u8>>(),
    );

    // mask inner
    builder.connect(
        &sha256_ipad.output(0).expect("sha256 missing output 0")[..],
        &masked_inner.input(0).expect("nbit_xor missing input 0")[..],
    );
    builder.connect(
        &mask_inner[..],
        &masked_inner.input(1).expect("nbit_xor missing input 1")[..],
    );

    // mask outer
    builder.connect(
        &sha256_opad.output(0).expect("sha256 missing output 0")[..],
        &masked_outer.input(0).expect("nbit_xor missing input 0")[..],
    );
    builder.connect(
        &mask_outer[..],
        &masked_outer.input(1).expect("nbit_xor missing input 1")[..],
    );

    let mut builder = builder.build_gates();

    let out_inner = builder.add_output(
        "MASKED_I",
        "32-byte masked HMAC inner hash state",
        ValueType::Bytes,
        256,
    );
    let out_outer = builder.add_output(
        "MASKED_O",
        "32-byte masked HMAC outer hash state",
        ValueType::Bytes,
        256,
    );

    builder.connect(
        &masked_inner.output(0).expect("nbit_xor missing output 0")[..],
        &out_inner[..],
    );
    builder.connect(
        &masked_outer.output(0).expect("nbit_xor missing output 0")[..],
        &out_outer[..],
    );

    builder.build_circuit().expect("failed to build c2")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{finalize_sha256_digest, partial_sha256_digest, test_circ};
    use mpc_circuits::Value;
    use rand::{thread_rng, Rng};

    #[test]
    fn test_c2() {
        let circ = c2();
        // Perform in the clear all the computations which happen inside the ciruit:
        let mut rng = thread_rng();

        let n_outer_hash_state: [u32; 8] = rng.gen();
        let u_inner_hash_p1: [u8; 32] = rng.gen();
        let u_p2: [u8; 16] = rng.gen();

        // * generate user's and notary's inside-the-GC-masks to mask the GC output
        let mask_n: [u8; 32] = rng.gen();
        let mask_u: [u8; 32] = rng.gen();

        // finalize the hash to get p1
        let p1 = finalize_sha256_digest(n_outer_hash_state, 64, &u_inner_hash_p1);
        // get master_secret
        let mut ms = [0u8; 48];
        ms[..32].copy_from_slice(&p1);
        ms[32..48].copy_from_slice(&u_p2[..16]);

        // * XOR ms (zero-padded to 64 bytes) with inner/outer padding of HMAC
        let mut ms_zeropadded = [0u8; 64];
        ms_zeropadded[0..48].copy_from_slice(&ms);

        let pms_ipad = ms_zeropadded.iter().map(|b| b ^ 0x36).collect::<Vec<u8>>();
        let pms_opad = ms_zeropadded.iter().map(|b| b ^ 0x5c).collect::<Vec<u8>>();

        // * hash the padded PMS
        let ohash_state = partial_sha256_digest(&pms_opad);
        let ihash_state = partial_sha256_digest(&pms_ipad);
        // convert into u8 array
        let ohash_state_u8: Vec<u8> = ohash_state
            .iter()
            .map(|u32t| u32t.to_be_bytes())
            .flatten()
            .collect();
        let ihash_state_u8: Vec<u8> = ihash_state
            .iter()
            .map(|u32t| u32t.to_be_bytes())
            .flatten()
            .collect();

        // * masked hash state are the expected circuit's outputs
        let expected_inner = ihash_state_u8
            .into_iter()
            .zip(mask_u)
            .map(|(b, mask)| b ^ mask)
            .collect::<Vec<u8>>();
        let expected_outer = ohash_state_u8
            .into_iter()
            .zip(mask_n)
            .map(|(b, mask)| b ^ mask)
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
                Value::Bytes(u_inner_hash_p1.into_iter().rev().collect()),
                Value::Bytes(u_p2.into_iter().rev().collect()),
                Value::Bytes(mask_u.iter().rev().copied().collect::<Vec<u8>>()),
                Value::Bytes(mask_n.iter().rev().copied().collect::<Vec<u8>>()),
            ],
            &[
                Value::Bytes(expected_inner.into_iter().rev().collect()),
                Value::Bytes(expected_outer.into_iter().rev().collect()),
            ],
        );
    }
}
