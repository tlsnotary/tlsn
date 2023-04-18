//! Core components used to implement garbled circuit protocols
//!
//! This module implements "half-gate" garbled circuits from the [Two Halves Make a Whole \[ZRE15\]](https://eprint.iacr.org/2014/756) paper.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]

pub(crate) mod circuit;
pub mod encoding;
mod evaluator;
mod generator;
pub mod msg;

pub use circuit::EncryptedGate;
pub use encoding::{
    state as label_state, ChaChaEncoder, Decoding, Delta, Encode, EncodedValue, Encoder,
    EncodingCommitment, EqualityCheck, Label, ValueError,
};
pub use evaluator::{Evaluator, EvaluatorError};
pub use generator::{Generator, GeneratorError};

/// Fixed key used for AES encryption
pub(crate) static CIPHER_FIXED_KEY: [u8; 16] = [69u8; 16];

#[cfg(test)]
mod tests {
    use aes::{Aes128, BlockEncrypt, NewBlockCipher};
    use mpc_circuits::{circuits::AES128, types::Value};
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;

    use super::*;

    #[test]
    fn test_and_gate() {
        use crate::{evaluator as ev, generator as gen};

        let mut rng = ChaCha12Rng::from_entropy();
        let mut cipher = Aes128::new_from_slice(&CIPHER_FIXED_KEY).unwrap();

        let delta = Delta::random(&mut rng);
        let x_0 = Label::random(&mut rng);
        let x_1 = x_0 ^ delta;
        let y_0 = Label::random(&mut rng);
        let y_1 = y_0 ^ delta;
        let gid: usize = 1;

        let (z_0, encrypted_gate) = gen::and_gate(&cipher, &x_0, &y_0, &delta, gid);
        let z_1 = z_0 ^ delta;

        assert_eq!(
            ev::and_gate(&mut cipher, &x_0, &y_1, &encrypted_gate, gid),
            z_0
        );
        assert_eq!(
            ev::and_gate(&mut cipher, &x_0, &y_1, &encrypted_gate, gid),
            z_0
        );
        assert_eq!(
            ev::and_gate(&mut cipher, &x_1, &y_0, &encrypted_gate, gid),
            z_0
        );
        assert_eq!(
            ev::and_gate(&mut cipher, &x_1, &y_1, &encrypted_gate, gid),
            z_1
        );
    }

    #[test]
    fn test_garble() {
        let encoder = ChaChaEncoder::new([0; 32]);

        let key = [69u8; 16];
        let msg = [42u8; 16];
        const BATCH_SIZE: usize = 1000;

        let expected: [u8; 16] = {
            let cipher = Aes128::new_from_slice(&key).unwrap();
            let mut out = msg.into();
            cipher.encrypt_block(&mut out);
            out.into()
        };

        let full_inputs: Vec<EncodedValue<label_state::Full>> = AES128
            .inputs()
            .iter()
            .map(|input| encoder.encode_by_type(0, &input.value_type()))
            .collect();

        let active_inputs: Vec<EncodedValue<label_state::Active>> = vec![
            full_inputs[0].clone().select(key).unwrap(),
            full_inputs[1].clone().select(msg).unwrap(),
        ];

        let mut gen = Generator::new(AES128.clone(), encoder.delta(), &full_inputs, true).unwrap();
        let mut ev = Evaluator::new(AES128.clone(), &active_inputs, true).unwrap();

        while !(gen.is_complete() && ev.is_complete()) {
            let mut batch = Vec::with_capacity(BATCH_SIZE);
            for enc_gate in gen.by_ref() {
                batch.push(enc_gate);
                if batch.len() == BATCH_SIZE {
                    break;
                }
            }
            ev.evaluate(batch.iter());
        }

        let full_outputs = gen.outputs().unwrap();
        let active_outputs = ev.outputs().unwrap();

        let gen_digest = gen.hash().unwrap();
        let ev_digest = ev.hash().unwrap();

        assert_eq!(gen_digest, ev_digest);

        let outputs: Vec<Value> = active_outputs
            .iter()
            .zip(full_outputs)
            .map(|(active_output, full_output)| {
                active_output.decode(&full_output.decoding()).unwrap()
            })
            .collect();

        let actual: [u8; 16] = outputs[0].clone().try_into().unwrap();

        assert_eq!(actual, expected);
    }
}
