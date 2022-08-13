pub mod circuit;
pub mod error;
pub mod evaluator;
pub mod exec;
pub mod generator;
mod label;

pub use circuit::{EncryptedGate, EvaluatedGarbledCircuit, FullGarbledCircuit, GarbledCircuit};
pub use error::{Error, InputError};
pub use evaluator::evaluate_garbled_circuit;
pub use generator::generate_garbled_circuit;
pub use label::{
    decode_labels, generate_input_labels, generate_label_pairs, Delta, InputLabels,
    SanitizedInputLabels, WireLabel, WireLabelPair,
};

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

    use crate::{garble::generate_input_labels, utils, Block};
    use mpc_circuits::{Circuit, AES_128_REVERSE};

    #[test]
    fn test_and_gate() {
        let mut rng = ChaCha12Rng::from_entropy();
        let mut cipher = Aes128::new(GenericArray::from_slice(&[0u8; 16]));

        let delta = Delta::random(&mut rng);
        let x_0 = Block::random(&mut rng);
        let x = WireLabelPair::new(0, x_0, x_0 ^ *delta);
        let y_0 = Block::random(&mut rng);
        let y = WireLabelPair::new(1, y_0, y_0 ^ *delta);
        let gid: usize = 1;

        let (z, encrypted_gate) = gen::and_gate(&cipher, &x, &y, 2, delta, gid);

        assert_eq!(
            ev::and_gate(
                &mut cipher,
                &x.select(false),
                &y.select(false),
                2,
                encrypted_gate.as_ref(),
                gid
            ),
            z.select(false)
        );
        assert_eq!(
            ev::and_gate(
                &mut cipher,
                &x.select(false),
                &y.select(true),
                2,
                encrypted_gate.as_ref(),
                gid
            ),
            z.select(false)
        );
        assert_eq!(
            ev::and_gate(
                &mut cipher,
                &x.select(true),
                &y.select(false),
                2,
                encrypted_gate.as_ref(),
                gid
            ),
            z.select(false)
        );
        assert_eq!(
            ev::and_gate(
                &mut cipher,
                &x.select(true),
                &y.select(true),
                2,
                encrypted_gate.as_ref(),
                gid
            ),
            z.select(true)
        );
    }

    #[test]
    fn test_xor_gate() {
        let mut rng = ChaCha12Rng::from_entropy();

        let delta = Delta::random(&mut rng);
        let x_0 = Block::random(&mut rng);
        let x = WireLabelPair::new(0, x_0, x_0 ^ *delta);
        let y_0 = Block::random(&mut rng);
        let y = WireLabelPair::new(1, y_0, y_0 ^ *delta);

        let z = gen::xor_gate(&x, &y, 2, delta);

        assert_eq!(
            ev::xor_gate(&x.select(false), &y.select(false), 2),
            z.select(false)
        );
        assert_eq!(
            ev::xor_gate(&x.select(false), &y.select(true), 2),
            z.select(true)
        );
        assert_eq!(
            ev::xor_gate(&x.select(true), &y.select(false), 2),
            z.select(true),
        );
        assert_eq!(
            ev::xor_gate(&x.select(true), &y.select(true), 2),
            z.select(false)
        );
    }

    #[test]
    fn test_aes_128() {
        let mut rng = ChaCha12Rng::from_entropy();
        let cipher = Aes128::new(GenericArray::from_slice(&[0u8; 16]));
        let circ = Arc::new(Circuit::load_bytes(AES_128_REVERSE).unwrap());

        let (input_labels, delta) = generate_input_labels(&mut rng, &circ, None);

        // Generator provides key
        let gen_input = circ.input(0).unwrap().to_value(&[false; 128]).unwrap();
        // Evaluator provides message
        let ev_input = circ.input(1).unwrap().to_value(&[false; 128]).unwrap();

        let gc =
            gen::generate_garbled_circuit(&cipher, circ.clone(), delta, &input_labels).unwrap();

        let gc = gc.to_evaluator(&[gen_input.clone()], true);

        // Evaluator typically receives these using OT
        let ev_input_labels = input_labels[1].select(&ev_input).unwrap();

        let evaluated_gc = ev::evaluate_garbled_circuit(&cipher, &gc, &[ev_input_labels]).unwrap();
        let output = evaluated_gc.decode().unwrap();

        let expected = circ.evaluate(&[gen_input, ev_input]).unwrap();

        assert_eq!(
            utils::boolvec_to_string(output[0].as_ref()),
            utils::boolvec_to_string(expected[0].as_ref())
        );
    }
}
