#![cfg(feature = "garble")]
// This example demonstrates how to garble and evaluate an AES128 encryption circuit.
// In practical situations wire labels would be communicated over a channel such as TCP and
// using an oblivious transfer protocol. For simplicity, this example shows how the generator
// and evaluator components work together in memory
use aes::cipher::{generic_array::GenericArray, NewBlockCipher};
use aes::Aes128;
use mpc_core::{
    circuit::{Circuit, CircuitInput},
    garble::{
        circuit::{CompleteGarbledCircuit, InputLabel},
        evaluator::*,
        generator::*,
    },
    utils::boolvec_to_u8vec,
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
    let mut cipher = Aes128::new(GenericArray::from_slice(&[0u8; 16]));
    let circ = Circuit::load("circuits/protobuf/aes_128_reverse.bin").unwrap();
    let gen = HalfGateGenerator::new();
    let ev = HalfGateEvaluator::new();

    let complete_gc: CompleteGarbledCircuit = gen.garble(&mut cipher, &mut rng, &circ).unwrap();

    // Circuit operates on reversed bits
    key.reverse();
    input.reverse();

    // Convert raw values to CircuitInputs, which indicate what input wire each value corresponds to
    let generator_inputs: Vec<CircuitInput> = input
        .into_iter()
        .enumerate()
        .map(|(id, value)| CircuitInput { id, value })
        .collect();

    // Convert `CompleteGarbledCircuit` to `Garbled Circuit` which strips data that the evaluator should not receive
    let gc = complete_gc.to_public(&generator_inputs);

    // Here we'll manually put together the evaluators input labels, this is usually retrieved using oblivious transfer
    let evaluator_input_labels: Vec<InputLabel> = key
        .into_iter()
        .zip(complete_gc.input_labels[128..256].iter())
        .enumerate()
        .map(|(id, (value, label))| InputLabel {
            id: id + 128,
            label: label[value as usize],
        })
        .collect();

    let outputs = ev
        .eval(&mut cipher, &circ, &gc, &evaluator_input_labels)
        .unwrap();

    let mut ciphertext = boolvec_to_u8vec(&outputs);
    ciphertext.reverse();
    println!("Ciphertext: {:02X?}", ciphertext);
}
