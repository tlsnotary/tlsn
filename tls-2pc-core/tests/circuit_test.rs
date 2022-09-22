// Here we test all the c*.bin circuits from ../circuits

use aes::{
    cipher::{generic_array::GenericArray, BlockEncrypt, NewBlockCipher},
    Aes128,
};
use hex::FromHex;
use mpc_circuits::Circuit;
use mpc_core::utils::{boolvec_to_u8vec, u8vec_to_boolvec, xor};
use num::{bigint::RandBigInt, BigUint, Zero};
use rand::{thread_rng, Rng};
use tls_2pc_core::{
    handshake::sha, CIRCUIT_1_BYTES, CIRCUIT_2_BYTES, CIRCUIT_3_BYTES, CIRCUIT_4_BYTES,
    CIRCUIT_5_BYTES, CIRCUIT_6_BYTES, CIRCUIT_7_BYTES,
};

/// NIST P-256 Prime
pub const P: &str = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";

// Evaluates the circuit "name" with the given inputs (and their sizes in bits)
// and the expected bitsize of outputs. Returns individual outputs as bytes.
fn evaluate_circuit(
    circ: &Circuit,
    inputs: Vec<Vec<u8>>,
    input_sizes: Vec<usize>,
    output_sizes: Vec<usize>,
) -> Vec<Vec<u8>> {
    // Each circuit's input's bit order is "least bits first". That's why we reverse each input
    // individually. (The individual circuit inputs are listed at the top of the c*.casm files)
    let mut all_inputs: Vec<Vec<bool>> = Vec::with_capacity(inputs.len());
    for i in 0..inputs.len() {
        // truncate the input to the exact amount of bits if necessary
        let mut tmp =
            u8vec_to_boolvec(&inputs[i])[(inputs[i].len() * 8 - input_sizes[i])..].to_vec();
        tmp.reverse();
        all_inputs.push(tmp);
    }
    let inputs: Vec<bool> = all_inputs.into_iter().flatten().collect();

    // same as with inputs, the outputs are "least bit first" and must be reversed individually
    let mut output = circ.evaluate(&inputs).unwrap();

    let mut outputs: Vec<Vec<u8>> = Vec::with_capacity(output_sizes.len());
    let mut pos: usize = 0;
    for i in 0..output_sizes.len() {
        let tmp = &mut output[pos..pos + output_sizes[i]];
        tmp.reverse();
        outputs.push(boolvec_to_u8vec(&tmp));
        pos += output_sizes[i];
    }
    outputs
}

// Tests correctness of the c1.casm circuit
fn circuit1(circ: &Circuit, u_share: BigUint, n_share: BigUint) {
    // Perform in the clear all the computations which happen inside the ciruit:
    let mut rng = thread_rng();

    let prime = <[u8; 32]>::from_hex(P).unwrap();
    let prime = BigUint::from_bytes_be(&prime);

    // * generate user's and notary's inside-the-GC-masks to mask the GC output
    let mask_n: [u8; 32] = rng.gen();
    let mask_u: [u8; 32] = rng.gen();

    // reduce pms mod prime if necessary
    let pms = (u_share.clone() + n_share.clone()) % prime;

    // * XOR pms (zero-padded to 64 bytes) with inner/outer padding of HMAC
    let ipad_64x = [0x36u8; 64];
    let opad_64x = [0x5cu8; 64];
    let mut pms_zeropadded = [0u8; 64];
    pms_zeropadded[0..32].copy_from_slice(&pms.to_bytes_be());

    let mut pms_ipad = [0u8; 64];
    let mut pms_opad = [0u8; 64];
    xor(&ipad_64x, &pms_zeropadded, &mut pms_ipad);
    xor(&opad_64x, &pms_zeropadded, &mut pms_opad);

    // * hash the padded PMS
    let ohash_state = sha::partial_sha256_digest(&pms_opad);
    let ihash_state = sha::partial_sha256_digest(&pms_ipad);
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
    let mut expected1 = [0u8; 32];
    let mut expected2 = [0u8; 32];
    xor(&ohash_state_u8, &mask_n, &mut expected1);
    xor(&ihash_state_u8, &mask_u, &mut expected2);

    // Evaluate the circuit.
    let outputs = evaluate_circuit(
        circ,
        vec![
            n_share.to_bytes_be().to_vec(),
            mask_n.to_vec(),
            u_share.to_bytes_be().to_vec(),
            mask_u.to_vec(),
        ],
        vec![256, 256, 256, 256],
        vec![256, 256],
    );
    assert_eq!(expected1.to_vec(), outputs[0]);
    assert_eq!(expected2.to_vec(), outputs[1]);
}

#[test]
// Test the circuit's code path when the sum of PMS shares DOES NOT overflow the prime
// and MUST NOT be reduced.
fn circuit1_no_overflow() {
    let mut rng = thread_rng();
    let circ = Circuit::load_bytes(CIRCUIT_1_BYTES).unwrap();

    let prime = <[u8; 32]>::from_hex(P).unwrap();
    let prime = BigUint::from_bytes_be(&prime);

    loop {
        // * generate user's and notary's random PMS shares in the field
        let n_share = rng.gen_biguint_range(&BigUint::zero(), &prime);
        let u_share = rng.gen_biguint_range(&BigUint::zero(), &prime);
        if (u_share.clone() + n_share.clone()) < prime {
            circuit1(&circ, u_share, n_share);
            break;
        }
    }
}

#[test]
// Test the circuit's code path when the sum of PMS shares DOES overflow the prime
// and MUST be reduced.
fn circuit1_with_overflow() {
    let mut rng = thread_rng();
    let circ = Circuit::load_bytes(CIRCUIT_1_BYTES).unwrap();

    let prime = <[u8; 32]>::from_hex(P).unwrap();
    let prime = BigUint::from_bytes_be(&prime);

    loop {
        // * generate user's and notary's random PMS shares in the field
        let n_share = rng.gen_biguint_range(&BigUint::zero(), &prime);
        let u_share = rng.gen_biguint_range(&BigUint::zero(), &prime);
        if (u_share.clone() + n_share.clone()) >= prime {
            circuit1(&circ, u_share, n_share);
            break;
        }
    }
}

#[test]
// Tests correctness of the c2.casm circuit
fn circuit2() {
    // Perform in the clear all the computations which happen inside the ciruit:
    let mut rng = thread_rng();

    let n_outer_hash_state: [u8; 32] = rng.gen();
    let n_output_mask: [u8; 32] = rng.gen();
    let u_inner_hash_p1: [u8; 32] = rng.gen();
    let u_p2: [u8; 16] = rng.gen();
    let u_output_mask: [u8; 32] = rng.gen();

    // convert outer_hash_state to the expected type [u32; 8]
    let mut n_outer_hash_state_u32 = [0u32; 8];
    for i in 0..8 {
        let mut tmp = [0u8; 4];
        tmp.copy_from_slice(&n_outer_hash_state[i * 4..(i + 1) * 4]);
        n_outer_hash_state_u32[i] = u32::from_be_bytes(tmp);
    }

    // finalize the hash to get p1
    let p1 = sha::finalize_sha256_digest(n_outer_hash_state_u32, 64, &u_inner_hash_p1);
    // get master_secret
    let mut ms = [0u8; 48];
    ms[..32].copy_from_slice(&p1);
    ms[32..48].copy_from_slice(&u_p2[..16]);

    // * XOR ms (zero-padded to 64 bytes) with inner/outer padding of HMAC
    let ipad_64x = [0x36u8; 64];
    let opad_64x = [0x5cu8; 64];
    let mut ms_zeropadded = [0u8; 64];
    ms_zeropadded[0..48].copy_from_slice(&ms);

    let mut ms_ipad = [0u8; 64];
    let mut ms_opad = [0u8; 64];
    xor(&ipad_64x, &ms_zeropadded, &mut ms_ipad);
    xor(&opad_64x, &ms_zeropadded, &mut ms_opad);

    // * hash the padded MS
    let ohash_state = sha::partial_sha256_digest(&ms_opad);
    let ihash_state = sha::partial_sha256_digest(&ms_ipad);
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
    let mut expected1 = [0u8; 32];
    let mut expected2 = [0u8; 32];
    xor(&ohash_state_u8, &n_output_mask, &mut expected1);
    xor(&ihash_state_u8, &u_output_mask, &mut expected2);

    // Evaluate the circuit.
    let outputs = evaluate_circuit(
        &Circuit::load_bytes(CIRCUIT_2_BYTES).unwrap(),
        vec![
            n_outer_hash_state.to_vec(),
            n_output_mask.to_vec(),
            u_inner_hash_p1.to_vec(),
            u_p2.to_vec(),
            u_output_mask.to_vec(),
        ],
        vec![256, 256, 256, 128, 256],
        vec![256, 256],
    );
    assert_eq!(expected1.to_vec(), outputs[0]);
    assert_eq!(expected2.to_vec(), outputs[1]);
}

#[test]
// Tests correctness of the c3.casm circuit
fn circuit3() {
    // Perform in the clear all the computations which happen inside the ciruit:
    let mut rng = thread_rng();

    let n_outer_hash_state: [u8; 32] = rng.gen();
    let n_output_mask1: [u8; 16] = rng.gen();
    let n_output_mask2: [u8; 16] = rng.gen();
    let n_output_mask3: [u8; 4] = rng.gen();
    let n_output_mask4: [u8; 4] = rng.gen();
    let u_inner_hash_p1: [u8; 32] = rng.gen();
    let u_inner_hash_p2: [u8; 32] = rng.gen();
    let u_output_mask1: [u8; 16] = rng.gen();
    let u_output_mask2: [u8; 16] = rng.gen();
    let u_output_mask3: [u8; 4] = rng.gen();
    let u_output_mask4: [u8; 4] = rng.gen();

    // convert outer_hash_state to the expected type [u32; 8]
    let mut n_outer_hash_state_u32 = [0u32; 8];
    for i in 0..8 {
        let mut tmp = [0u8; 4];
        tmp.copy_from_slice(&n_outer_hash_state[i * 4..(i + 1) * 4]);
        n_outer_hash_state_u32[i] = u32::from_be_bytes(tmp);
    }

    // finalize the hash to get p1
    let p1 = sha::finalize_sha256_digest(n_outer_hash_state_u32, 64, &u_inner_hash_p1);
    // finalize the hash to get p2
    let p2 = sha::finalize_sha256_digest(n_outer_hash_state_u32, 64, &u_inner_hash_p2);

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

    // XOR each keys with Notary's mask and then with User's mask
    let mut swk_masked = [0u8; 16];
    xor(&swk, &n_output_mask1, &mut swk_masked);
    xor(&swk_masked.clone(), &u_output_mask1, &mut swk_masked);
    let mut cwk_masked = [0u8; 16];
    xor(&cwk, &n_output_mask2, &mut cwk_masked);
    xor(&cwk_masked.clone(), &u_output_mask2, &mut cwk_masked);
    let mut siv_masked = [0u8; 4];
    xor(&siv, &n_output_mask3, &mut siv_masked);
    xor(&siv_masked.clone(), &u_output_mask3, &mut siv_masked);
    let mut civ_masked = [0u8; 4];
    xor(&civ, &n_output_mask4, &mut civ_masked);
    xor(&civ_masked.clone(), &u_output_mask4, &mut civ_masked);

    // Evaluate the circuit.
    let outputs = evaluate_circuit(
        &Circuit::load_bytes(CIRCUIT_3_BYTES).unwrap(),
        vec![
            n_outer_hash_state.to_vec(),
            n_output_mask1.to_vec(),
            n_output_mask2.to_vec(),
            n_output_mask3.to_vec(),
            n_output_mask4.to_vec(),
            u_inner_hash_p1.to_vec(),
            u_inner_hash_p2.to_vec(),
            u_output_mask1.to_vec(),
            u_output_mask2.to_vec(),
            u_output_mask3.to_vec(),
            u_output_mask4.to_vec(),
        ],
        vec![256, 128, 128, 32, 32, 256, 256, 128, 128, 32, 32],
        vec![128, 128, 32, 32],
    );
    assert_eq!(swk_masked.to_vec(), outputs[0]);
    assert_eq!(cwk_masked.to_vec(), outputs[1]);
    assert_eq!(siv_masked.to_vec(), outputs[2]);
    assert_eq!(civ_masked.to_vec(), outputs[3]);
}

#[test]
// Tests correctness of the c4.casm circuit
fn circuit4() {
    // Perform in the clear all the computations which happen inside the ciruit:
    let mut rng = thread_rng();

    let n_swk: [u8; 16] = rng.gen();
    let n_cwk: [u8; 16] = rng.gen();
    let n_siv: [u8; 4] = rng.gen();
    let n_civ: [u8; 4] = rng.gen();
    let n_output_mask5: [u8; 16] = rng.gen();
    let n_output_mask6: [u8; 16] = rng.gen();
    let u_swk: [u8; 16] = rng.gen();
    let u_cwk: [u8; 16] = rng.gen();
    let u_siv: [u8; 4] = rng.gen();
    let u_civ: [u8; 4] = rng.gen();
    let u_output_mask5: [u8; 16] = rng.gen();
    let u_output_mask6: [u8; 16] = rng.gen();
    let u_output_mask7: [u8; 16] = rng.gen();

    // combine key shares
    let mut swk = [0u8; 16];
    xor(&n_swk, &u_swk, &mut swk);
    let mut cwk = [0u8; 16];
    xor(&n_cwk, &u_cwk, &mut cwk);
    let mut siv = [0u8; 4];
    xor(&n_siv, &u_siv, &mut siv);
    let mut civ = [0u8; 4];
    xor(&n_civ, &u_civ, &mut civ);

    // set AES key
    let key = GenericArray::clone_from_slice(&cwk);
    let cipher = Aes128::new(&key);

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
    let mut mac_key_masked = [0u8; 16];
    xor(&mac_key, &n_output_mask5, &mut mac_key_masked);
    xor(
        &mac_key_masked.clone(),
        &u_output_mask5,
        &mut mac_key_masked,
    );
    let mut gctr_block_masked = [0u8; 16];
    xor(&gctr_block, &n_output_mask6, &mut gctr_block_masked);
    xor(
        &gctr_block_masked.clone(),
        &u_output_mask6,
        &mut gctr_block_masked,
    );

    // XOR the first block with User's mask
    let mut first_block_masked = [0u8; 16];
    xor(&first_block, &u_output_mask7, &mut first_block_masked);

    // Evaluate the circuit.
    let outputs = evaluate_circuit(
        &Circuit::load_bytes(CIRCUIT_4_BYTES).unwrap(),
        vec![
            n_swk.to_vec(),
            n_cwk.to_vec(),
            n_siv.to_vec(),
            n_civ.to_vec(),
            n_output_mask5.to_vec(),
            n_output_mask6.to_vec(),
            u_swk.to_vec(),
            u_cwk.to_vec(),
            u_siv.to_vec(),
            u_civ.to_vec(),
            u_output_mask5.to_vec(),
            u_output_mask6.to_vec(),
            u_output_mask7.to_vec(),
        ],
        vec![128, 128, 32, 32, 128, 128, 128, 128, 32, 32, 128, 128, 128],
        vec![128, 128, 128],
    );
    assert_eq!(mac_key_masked.to_vec(), outputs[0]);
    assert_eq!(gctr_block_masked.to_vec(), outputs[1]);
    assert_eq!(first_block_masked.to_vec(), outputs[2]);
}

#[test]
// Tests correctness of the c5.casm circuit
fn circuit5() {
    // Perform in the clear all the computations which happen inside the ciruit:
    let mut rng = thread_rng();

    let n_outer_hash_state_p1: [u8; 32] = rng.gen();
    let n_swk: [u8; 16] = rng.gen();
    let n_siv: [u8; 4] = rng.gen();
    let n_output_mask1: [u8; 16] = rng.gen();
    let n_output_mask2: [u8; 16] = rng.gen();
    let u_inner_hash_state_p1: [u8; 32] = rng.gen();
    let u_swk: [u8; 16] = rng.gen();
    let u_siv: [u8; 4] = rng.gen();
    let u_server_finished_nonce: [u8; 8] = rng.gen();
    let u_output_mask1: [u8; 16] = rng.gen();
    let u_output_mask2: [u8; 16] = rng.gen();
    let u_output_mask3: [u8; 16] = rng.gen();
    let u_output_mask4: [u8; 12] = rng.gen();

    // convert outer_hash_state to the expected type [u32; 8]
    let mut n_outer_hash_state_p1_u32 = [0u32; 8];
    for i in 0..8 {
        let mut tmp = [0u8; 4];
        tmp.copy_from_slice(&n_outer_hash_state_p1[i * 4..(i + 1) * 4]);
        n_outer_hash_state_p1_u32[i] = u32::from_be_bytes(tmp);
    }

    // finalize the hash to get p1
    let p1 = sha::finalize_sha256_digest(n_outer_hash_state_p1_u32, 64, &u_inner_hash_state_p1);
    let mut verify_data = [0u8; 12];
    verify_data.copy_from_slice(&p1[0..12]);

    // combine key shares
    let mut swk = [0u8; 16];
    xor(&n_swk, &u_swk, &mut swk);
    let mut siv = [0u8; 4];
    xor(&n_siv, &u_siv, &mut siv);

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
    msg[4..12].copy_from_slice(&u_server_finished_nonce);
    msg[12..16].copy_from_slice(&counter);
    let mut msg = GenericArray::clone_from_slice(&msg);
    cipher.encrypt_block(&mut msg);
    let gctr_block = msg;

    // AES-ECB encrypt a block with counter==2 and nonce from Server_Finished
    let counter: [u8; 4] = 2u32.to_be_bytes();
    let mut msg = [0u8; 16];
    msg[0..4].copy_from_slice(&siv);
    msg[4..12].copy_from_slice(&u_server_finished_nonce);
    msg[12..16].copy_from_slice(&counter);
    let mut msg = GenericArray::clone_from_slice(&msg);
    cipher.encrypt_block(&mut msg);
    let first_block = msg;

    // XOR MAC key and GCTR block with Notary's mask and then with User's mask
    let mut mac_key_masked = [0u8; 16];
    xor(&mac_key, &n_output_mask1, &mut mac_key_masked);
    xor(
        &mac_key_masked.clone(),
        &u_output_mask1,
        &mut mac_key_masked,
    );
    let mut gctr_block_masked = [0u8; 16];
    xor(&gctr_block, &n_output_mask2, &mut gctr_block_masked);
    xor(
        &gctr_block_masked.clone(),
        &u_output_mask2,
        &mut gctr_block_masked,
    );

    // XOR the first block and verify_data with User's mask
    let mut first_block_masked = [0u8; 16];
    xor(&first_block, &u_output_mask3, &mut first_block_masked);
    let mut verify_data_masked = [0u8; 12];
    xor(&verify_data, &u_output_mask4, &mut verify_data_masked);

    // Evaluate the circuit.
    let outputs = evaluate_circuit(
        &Circuit::load_bytes(CIRCUIT_5_BYTES).unwrap(),
        vec![
            n_outer_hash_state_p1.to_vec(),
            n_swk.to_vec(),
            n_siv.to_vec(),
            n_output_mask1.to_vec(),
            n_output_mask2.to_vec(),
            u_inner_hash_state_p1.to_vec(),
            u_swk.to_vec(),
            u_siv.to_vec(),
            u_server_finished_nonce.to_vec(),
            u_output_mask1.to_vec(),
            u_output_mask2.to_vec(),
            u_output_mask3.to_vec(),
            u_output_mask4.to_vec(),
        ],
        vec![256, 128, 32, 128, 128, 256, 128, 32, 64, 128, 128, 128, 96],
        vec![128, 128, 128, 96],
    );
    assert_eq!(mac_key_masked.to_vec(), outputs[0]);
    assert_eq!(gctr_block_masked.to_vec(), outputs[1]);
    assert_eq!(first_block_masked.to_vec(), outputs[2]);
    assert_eq!(verify_data_masked.to_vec(), outputs[3]);
}

#[test]
// Tests correctness of the c6.casm circuit
fn circuit6() {
    // Perform in the clear all the computations which happen inside the ciruit:
    let mut rng = thread_rng();

    let n_cwk: [u8; 16] = rng.gen();
    let n_civ: [u8; 4] = rng.gen();
    let u_cwk: [u8; 16] = rng.gen();
    let u_civ: [u8; 4] = rng.gen();
    let u_output_mask: [u8; 16] = rng.gen();
    let u_nonce: [u8; 2] = rng.gen();
    let u_counter: [u8; 2] = rng.gen();

    // combine key shares
    let mut cwk = [0u8; 16];
    xor(&n_cwk, &u_cwk, &mut cwk);
    let mut civ = [0u8; 4];
    xor(&n_civ, &u_civ, &mut civ);

    // set AES key
    let key = GenericArray::clone_from_slice(&cwk);
    let cipher = Aes128::new(&key);

    // AES-ECB encrypt a block with counter and nonce from the User's input
    let mut msg = [0u8; 16];
    msg[0..4].copy_from_slice(&civ);
    // 54 msb of nonce must be zero
    let mut nonce_bool = vec![false; 64];
    nonce_bool[54..64].copy_from_slice(&u8vec_to_boolvec(&u_nonce)[6..16]);
    msg[4..12].copy_from_slice(&boolvec_to_u8vec(&nonce_bool));
    // 22 msb of counter must be zero
    let mut counter_bool = vec![false; 32];
    counter_bool[22..32].copy_from_slice(&u8vec_to_boolvec(&u_counter)[6..16]);
    msg[12..16].copy_from_slice(&boolvec_to_u8vec(&counter_bool));
    let mut msg = GenericArray::clone_from_slice(&msg);
    cipher.encrypt_block(&mut msg);
    let encr_block = msg;

    // XOR-mask the encrypted block with User's mask
    let mut encr_block_masked = [0u8; 16];
    xor(&encr_block, &u_output_mask, &mut encr_block_masked);

    // Evaluate the circuit.
    let outputs = evaluate_circuit(
        &Circuit::load_bytes(CIRCUIT_6_BYTES).unwrap(),
        vec![
            n_cwk.to_vec(),
            n_civ.to_vec(),
            u_cwk.to_vec(),
            u_civ.to_vec(),
            u_output_mask.to_vec(),
            u_nonce.to_vec(),
            u_counter.to_vec(),
        ],
        vec![128, 32, 128, 32, 128, 10, 10],
        vec![128],
    );
    assert_eq!(encr_block_masked.to_vec(), outputs[0]);
}

#[test]
// Tests correctness of the c7.casm circuit
fn circuit7() {
    // Perform in the clear all the computations which happen inside the ciruit:
    let mut rng = thread_rng();

    let n_cwk: [u8; 16] = rng.gen();
    let n_civ: [u8; 4] = rng.gen();
    let n_output_mask: [u8; 16] = rng.gen();
    let u_cwk: [u8; 16] = rng.gen();
    let u_civ: [u8; 4] = rng.gen();
    let u_output_mask: [u8; 16] = rng.gen();
    let u_nonce: [u8; 2] = rng.gen();

    // combine key shares
    let mut cwk = [0u8; 16];
    xor(&n_cwk, &u_cwk, &mut cwk);
    let mut civ = [0u8; 4];
    xor(&n_civ, &u_civ, &mut civ);

    // set AES key
    let key = GenericArray::clone_from_slice(&cwk);
    let cipher = Aes128::new(&key);

    // AES-ECB encrypt a block with counter==1 and nonce from the User's input
    let mut msg = [0u8; 16];
    msg[0..4].copy_from_slice(&civ);
    // 48 msb of nonce must be zero
    let mut nonce_bool = vec![false; 64];
    nonce_bool[48..64].copy_from_slice(&u8vec_to_boolvec(&u_nonce)[0..16]);
    msg[4..12].copy_from_slice(&boolvec_to_u8vec(&nonce_bool));
    let counter: [u8; 4] = 1u32.to_be_bytes();
    msg[12..16].copy_from_slice(&counter);
    let mut msg = GenericArray::clone_from_slice(&msg);
    cipher.encrypt_block(&mut msg);
    let gctr_block = msg;

    // XOR-mask the encrypted block with the Notary's mask and with the Client's mask
    let mut gctr_block_masked = [0u8; 16];
    xor(&gctr_block, &u_output_mask, &mut gctr_block_masked);
    xor(
        &gctr_block_masked.clone(),
        &n_output_mask,
        &mut gctr_block_masked,
    );

    // Evaluate the circuit.
    let outputs = evaluate_circuit(
        &Circuit::load_bytes(CIRCUIT_7_BYTES).unwrap(),
        vec![
            n_cwk.to_vec(),
            n_civ.to_vec(),
            n_output_mask.to_vec(),
            u_cwk.to_vec(),
            u_civ.to_vec(),
            u_output_mask.to_vec(),
            u_nonce.to_vec(),
        ],
        vec![128, 32, 128, 128, 32, 128, 16],
        vec![128],
    );
    assert_eq!(gctr_block_masked.to_vec(), outputs[0]);
}
