#![cfg(feature = "garble")]
use std::sync::Arc;

// This example demonstrates how to garble and evaluate an AES128 encryption circuit.
// In practical situations wire labels would be communicated over a channel such as TCP and
// using an oblivious transfer protocol. For simplicity, this example shows how the generator
// and evaluator components work together in memory
use aes::cipher::{generic_array::GenericArray, NewBlockCipher};
use aes::Aes128;
use mpc_circuits::{Circuit, AES_128_REVERSE};
use mpc_core::garble::circuit::{prepare_inputs, BinaryLabel};
use mpc_core::{
    garble::{
        circuit::{generate_labels, generate_public_labels},
        decode, evaluator as ev, generator as gen,
    },
    utils::{boolvec_to_u8vec, choose},
};
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;

fn main() {
    let mut input = vec![false; 128];
    let mut key = vec![false; 128];

    println!(
        "Input: {:02X?}\nKey: {:02X?}",
        boolvec_to_u8vec(&input),
        boolvec_to_u8vec(&key)
    );

    let mut rng = ChaCha12Rng::from_entropy();
    let cipher = Aes128::new(GenericArray::from_slice(&[0u8; 16]));
    let circ = Arc::new(Circuit::load_bytes(AES_128_REVERSE).unwrap());

    let (input_labels, delta) = generate_labels(&mut rng, None, 256);
    let public_labels = generate_public_labels(&mut rng, &delta);

    let full_gc =
        gen::generate_garbled_circuit(&cipher, circ.clone(), &delta, &input_labels, &public_labels)
            .unwrap();

    // Circuit operates on reversed bits
    key.reverse();
    input.reverse();

    let gen_inputs: Vec<BinaryLabel> = choose(&input_labels[..128], &input)
        .into_iter()
        .enumerate()
        .map(|(id, value)| BinaryLabel { id, value })
        .collect();

    // Convert `FullGarbledCircuit` to `GarbledCircuit` which strips data that the evaluator should not receive
    let gc = full_gc.to_evaluator(&gen_inputs, true);

    // This is usually retrieved using oblivious transfer
    let ev_inputs: Vec<BinaryLabel> = choose(&input_labels[128..], &key)
        .into_iter()
        .enumerate()
        .map(|(id, value)| BinaryLabel {
            id: id + 128,
            value,
        })
        .collect();

    let inputs = [gen_inputs, ev_inputs].concat();
    let inputs = prepare_inputs(&circ, inputs).unwrap();

    let output_labels =
        ev::eval(&cipher, &circ, &inputs, &public_labels, &gc.encrypted_gates).unwrap();

    let output = decode(&output_labels, &gc.decoding.unwrap());

    let mut ciphertext = boolvec_to_u8vec(&output);
    ciphertext.reverse();
    println!("Ciphertext: {:02X?}", ciphertext);
}
