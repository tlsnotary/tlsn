pub mod circuit;
pub mod error;
pub mod evaluator;
mod execution;
pub mod generator;

pub use circuit::{
    decode, generate_labels, generate_public_labels, EncryptedGate, FullGarbledCircuit,
    GarbledCircuit,
};
pub use error::{Error, InputError};
pub use evaluator::evaluate_garbled_circuit;
pub use generator::generate_garbled_circuit;

#[derive(Debug, Clone)]
pub enum GarbleMessage {}

#[cfg(test)]
mod tests {
    use super::{evaluator as ev, generator as gen, *};
    use aes::{
        cipher::{generic_array::GenericArray, NewBlockCipher},
        Aes128,
    };
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;
    use std::sync::Arc;

    use crate::{garble::circuit::generate_labels, utils, Block};
    use mpc_circuits::{Circuit, AES_128_REVERSE};

    #[test]
    fn test_and_gate() {
        let mut rng = ChaCha12Rng::from_entropy();
        let mut cipher = Aes128::new(GenericArray::from_slice(&[0u8; 16]));

        let mut delta = Block::random(&mut rng);
        delta.set_lsb();
        let x_0 = Block::random(&mut rng);
        let x = [x_0, x_0 ^ delta];
        let y_0 = Block::random(&mut rng);
        let y = [y_0, y_0 ^ delta];
        let gid: usize = 1;

        let (z, encrypted_gate) = gen::and_gate(&cipher, &x, &y, &delta, gid);

        assert_eq!(
            ev::and_gate(&mut cipher, &x[0], &y[0], &encrypted_gate, gid),
            z[0]
        );
        assert_eq!(
            ev::and_gate(&mut cipher, &x[0], &y[1], &encrypted_gate, gid),
            z[0]
        );
        assert_eq!(
            ev::and_gate(&mut cipher, &x[1], &y[0], &encrypted_gate, gid),
            z[0]
        );
        assert_eq!(
            ev::and_gate(&mut cipher, &x[1], &y[1], &encrypted_gate, gid),
            z[1]
        );
    }

    #[test]
    fn test_xor_gate() {
        let mut rng = ChaCha12Rng::from_entropy();

        let mut delta = Block::random(&mut rng);
        delta.set_lsb();
        let x_0 = Block::random(&mut rng);
        let x = [x_0, x_0 ^ delta];
        let y_0 = Block::random(&mut rng);
        let y = [y_0, y_0 ^ delta];

        let z = gen::xor_gate(&x, &y, &delta);

        assert_eq!(ev::xor_gate(&x[0], &y[0]), z[0]);
        assert_eq!(ev::xor_gate(&x[0], &y[1]), z[1]);
        assert_eq!(ev::xor_gate(&x[1], &y[0]), z[1]);
        assert_eq!(ev::xor_gate(&x[1], &y[1]), z[0]);
    }

    #[test]
    fn test_inv_gate() {
        let mut rng = ChaCha12Rng::from_entropy();

        let mut delta = Block::random(&mut rng);
        delta.set_lsb();
        let public_labels = [Block::random(&mut rng), Block::random(&mut rng) ^ delta];
        let x_0 = Block::random(&mut rng);
        let x = [x_0, x_0 ^ delta];

        let z = gen::inv_gate(&x, &public_labels, &delta);
        assert_eq!(ev::inv_gate(&x[0], &public_labels[1]), z[1]);
        assert_eq!(ev::inv_gate(&x[1], &public_labels[1]), z[0]);
    }

    #[test]
    fn test_aes_128() {
        let mut rng = ChaCha12Rng::from_entropy();
        let cipher = Aes128::new(GenericArray::from_slice(&[0u8; 16]));
        let circ = Arc::new(Circuit::load_bytes(AES_128_REVERSE).unwrap());

        let (input_labels, delta) = generate_labels(&mut rng, None, 256, 0);
        let public_labels = generate_public_labels(&mut rng, &delta);

        let gc = gen::generate_garbled_circuit(
            &cipher,
            circ.clone(),
            &delta,
            &input_labels,
            &public_labels,
        )
        .unwrap();
        let gc = gc.to_evaluator(&[], true);

        let choice = [true; 256];
        let input_labels = utils::choose(&input_labels, &choice);

        let output_labels = ev::evaluate_garbled_circuit(&cipher, &gc, &input_labels).unwrap();

        let output = decode(&output_labels, &gc.decoding.unwrap());

        let expected = circ.evaluate(&choice).unwrap();
        assert_eq!(
            utils::boolvec_to_string(&output),
            utils::boolvec_to_string(&expected)
        );
    }
}
