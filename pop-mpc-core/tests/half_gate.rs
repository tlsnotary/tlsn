use aes::cipher::{generic_array::GenericArray, NewBlockCipher};
use aes::Aes128;
use pop_mpc_core::garble::circuit::InputLabel;
use pop_mpc_core::{
    block::Block,
    circuit::{Circuit, CircuitInput},
    garble::{evaluator::*, generator::*},
    utils::boolvec_to_string,
};
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;

#[test]
fn test_and_gate() {
    let mut rng = ChaCha12Rng::from_entropy();
    let mut cipher = Aes128::new(GenericArray::from_slice(&[0u8; 16]));
    let gen = HalfGateGenerator::new();
    let ev = HalfGateEvaluator::new();

    let mut delta = Block::random(&mut rng);
    delta.set_lsb();
    let x_0 = Block::random(&mut rng);
    let x = [x_0, x_0 ^ delta];
    let y_0 = Block::random(&mut rng);
    let y = [y_0, y_0 ^ delta];
    let gid: usize = 1;

    let (z, table) = gen.and_gate(&mut cipher, x, y, delta, gid);

    assert_eq!(ev.and_gate(&mut cipher, x[0], y[0], table, gid), z[0]);
    assert_eq!(ev.and_gate(&mut cipher, x[0], y[1], table, gid), z[0]);
    assert_eq!(ev.and_gate(&mut cipher, x[1], y[0], table, gid), z[0]);
    assert_eq!(ev.and_gate(&mut cipher, x[1], y[1], table, gid), z[1]);
}

#[test]
fn test_xor_gate() {
    let mut rng = ChaCha12Rng::from_entropy();
    let gen = HalfGateGenerator::new();
    let ev = HalfGateEvaluator::new();

    let mut delta = Block::random(&mut rng);
    delta.set_lsb();
    let x_0 = Block::random(&mut rng);
    let x = [x_0, x_0 ^ delta];
    let y_0 = Block::random(&mut rng);
    let y = [y_0, y_0 ^ delta];

    let z = gen.xor_gate(x, y, delta);

    assert_eq!(ev.xor_gate(x[0], y[0]), z[0]);
    assert_eq!(ev.xor_gate(x[0], y[1]), z[1]);
    assert_eq!(ev.xor_gate(x[1], y[0]), z[1]);
    assert_eq!(ev.xor_gate(x[1], y[1]), z[0]);
}

#[test]
fn test_inv_gate() {
    let mut rng = ChaCha12Rng::from_entropy();
    let gen = HalfGateGenerator::new();
    let ev = HalfGateEvaluator::new();

    let mut delta = Block::random(&mut rng);
    delta.set_lsb();
    let public_labels = [Block::random(&mut rng), Block::random(&mut rng) ^ delta];
    let x_0 = Block::random(&mut rng);
    let x = [x_0, x_0 ^ delta];

    let z = gen.inv_gate(x, public_labels, delta);
    assert_eq!(ev.inv_gate(x[0], public_labels[1]), z[1]);
    assert_eq!(ev.inv_gate(x[1], public_labels[1]), z[0]);
}

#[test]
fn test_aes_128() {
    let mut rng = ChaCha12Rng::from_entropy();
    let mut cipher = Aes128::new(GenericArray::from_slice(&[0u8; 16]));
    let circ = Circuit::parse("circuits/aes_128_reverse.txt").unwrap();
    let gen = HalfGateGenerator::new();
    let ev = HalfGateEvaluator::new();

    let gc = gen.garble(&mut cipher, &mut rng, &circ).unwrap();

    let generator_inputs = vec![true; 128];
    let generator_inputs: Vec<CircuitInput> = generator_inputs
        .into_iter()
        .enumerate()
        .map(|(id, value)| CircuitInput { id, value })
        .collect();

    let evaluator_inputs = vec![true; 128];
    let evaluator_inputs: Vec<CircuitInput> = evaluator_inputs
        .into_iter()
        .enumerate()
        .map(|(id, value)| CircuitInput {
            id: id + 128,
            value,
        })
        .collect();
    let evaluator_input_labels: Vec<InputLabel> = gc.input_labels[128..256]
        .iter()
        .zip(evaluator_inputs.iter())
        .map(|(label, input)| InputLabel {
            id: input.id,
            label: label[input.value as usize],
        })
        .collect();

    let gc = gc.to_public(&generator_inputs);
    let outputs = ev
        .eval(&mut cipher, &circ, &gc, evaluator_input_labels)
        .unwrap();

    let expected = circ
        .eval([generator_inputs, evaluator_inputs].concat())
        .unwrap();
    assert_eq!(boolvec_to_string(&outputs), boolvec_to_string(&expected));
}
