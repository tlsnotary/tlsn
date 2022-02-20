use aes::cipher::{generic_array::GenericArray, NewBlockCipher};
use aes::Aes128;
use pop_mpc::{
    block::Block,
    circuit::Circuit,
    garble::{evaluator::*, generator::*},
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

    let a: Vec<u8> = vec![1; 128];

    let expected = circ.eval(vec![a.clone(), a.clone()]).unwrap();

    let inputs = [a.clone(), a.clone()].concat();
    let input_labels = gc
        .input_labels
        .iter()
        .zip(inputs)
        .map(|(label, input)| label[input as usize])
        .collect();

    let output_labels = ev.eval(&mut cipher, &circ, &gc, input_labels).unwrap();
    let mut outputs: Vec<u8> = Vec::with_capacity(circ.noutput_wires);
    for (i, label) in output_labels.iter().enumerate() {
        outputs.push((label.lsb() ^ gc.output_bits[i]) as u8);
    }
    assert_eq!(outputs, expected);
}
