use aes::cipher::{generic_array::GenericArray, NewBlockCipher};
use aes::Aes128;
use mpc_core::circuit::{Circuit, CircuitInput};
use mpc_core::garble::generator::{GarbledCircuitGenerator, HalfGateGenerator};
use mpc_core::proto::garble::GarbledCircuit;
use prost::Message;
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;
use std::env;

// Pass in the circuit name as a cli argument to measure the garbled size
fn main() {
    let args: Vec<String> = env::args().collect();
    let circ = Circuit::load(format!("circuits/protobuf/{}.bin", args[1]).as_str()).unwrap();
    let gen = HalfGateGenerator::new();
    let mut rng = ChaCha12Rng::from_entropy();
    let mut cipher = Aes128::new(GenericArray::from_slice(&[0u8; 16]));
    let gc = gen.garble(&mut cipher, &mut rng, &circ).unwrap();
    let inputs = vec![false; circ.ninputs]
        .into_iter()
        .enumerate()
        .map(|(i, v)| CircuitInput { id: i, value: v })
        .collect();
    let gc = gc.to_public(&inputs);
    println!(
        "{}: {} kilobytes",
        args[1],
        GarbledCircuit::from(gc).encode_to_vec().len() / 1024
    );
}
