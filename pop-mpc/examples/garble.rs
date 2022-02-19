// This example demonstrates how to garble and evaluate an AES128 encryption circuit.
// In practical situations wire labels would be communicated over a channel such as TCP and
// using an oblivious transfer protocol. For simplicity, this example shows how the generator
// and evaluator components work together in memory

use aes::cipher::{generic_array::GenericArray, NewBlockCipher};
use aes::Aes128;
use pop_mpc::{
    circuit::Circuit,
    garble::{circuit::GarbledCircuit, evaluator::*, generator::*},
    utils::boolvec_to_u8vec,
};
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;

fn bits_to_bytes(bits: &Vec<u8>) -> Vec<u8> {
    let b: Vec<bool> = bits.iter().map(|b| *b == 1).collect();
    boolvec_to_u8vec(&b)
}

fn main() {
    let mut input = vec![0u8; 128];
    let mut key = vec![0u8; 128];

    println!(
        "Input: {:02X?}\nKey: {:02X?}",
        bits_to_bytes(&input),
        bits_to_bytes(&key)
    );

    let mut rng = ChaCha12Rng::from_entropy();
    let mut cipher = Aes128::new(GenericArray::from_slice(&[0u8; 16]));
    let circ = Circuit::parse("circuits/aes_128_reverse.txt").unwrap();
    let gen = HalfGateGenerator;
    let ev = HalfGateEvaluator;

    let gc: GarbledCircuit = gen.garble(&mut cipher, &mut rng, &circ).unwrap();

    // Circuit operates on reversed bits
    key.reverse();
    input.reverse();

    let inputs = [key, input].concat();
    // Map input bits to corresponding wire labels
    let input_labels = gc
        .input_labels
        .iter()
        .zip(inputs)
        .map(|(label, input)| label[input as usize])
        .collect();

    let output_labels = ev.eval(&mut cipher, &circ, &gc, input_labels).unwrap();

    // Map output labels back to truth bits
    let mut outputs: Vec<u8> = Vec::with_capacity(circ.noutput_wires);
    for (i, label) in output_labels.iter().enumerate() {
        outputs.push((label.lsb() ^ gc.output_bits[i]) as u8);
    }

    let mut ciphertext = bits_to_bytes(&outputs);
    ciphertext.reverse();
    println!("Ciphertext: {:02X?}", ciphertext);
}
