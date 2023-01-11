pub mod builder;
pub mod circuit;
pub mod circuits;
mod error;
pub(crate) mod group;
mod input;
mod output;
pub mod parse;
pub mod proto;
mod spec;
pub mod utils;
mod value;

pub use circuit::{Circuit, CircuitId, Gate};
pub use error::{CircuitError, GroupError, ValueError};
pub use group::{Group, GroupId, GroupValue, WireGroup};
pub use input::Input;
pub use output::Output;
pub use spec::CircuitSpec;
pub use value::{Value, ValueType};

/// Group of wires corresponding to a circuit input
pub type InputValue = GroupValue<Input>;
/// Group of wires corresponding to a circuit output
pub type OutputValue = GroupValue<Output>;

#[cfg(feature = "aes_128_reverse")]
pub static AES_128_REVERSE: &'static [u8] =
    std::include_bytes!("../circuits/bin/aes_128_reverse.bin");
#[cfg(feature = "adder64")]
pub static ADDER_64: &'static [u8] = std::include_bytes!("../circuits/bin/adder64.bin");
#[cfg(feature = "sha256")]
pub static SHA_256: &'static [u8] = std::include_bytes!("../circuits/bin/sha256.bin");

#[cfg(test)]
mod tests {
    use crate::InputValue;

    use super::*;

    fn test_circ(circ: &Circuit, inputs: &[Value], expected: &[Value]) {
        let inputs: Vec<InputValue> = inputs
            .iter()
            .zip(circ.inputs.iter())
            .map(|(value, input)| input.clone().to_value(value.clone()).unwrap())
            .collect();
        let outputs = circ.evaluate(&inputs).unwrap();
        for (output, expected) in outputs.iter().zip(expected) {
            if output.value() != expected {
                let report = format!(
                    "Circuit {}\n{}{}Expected: {:?}",
                    circ.description(),
                    inputs
                        .iter()
                        .enumerate()
                        .map(|(id, input)| format!("Input {}:  {:?}\n", id, input.value()))
                        .collect::<Vec<String>>()
                        .join(""),
                    format!("Output {}: {:?}\n", output.index(), output.value()),
                    expected
                );
                panic!("{}", report.to_string());
            }
        }
    }

    #[cfg(feature = "adder64")]
    mod adder_64 {
        use super::*;

        #[test]
        fn test_adder_64() {
            let circ = Circuit::load_bytes(ADDER_64).unwrap();

            test_circ(
                &circ,
                &[Value::from(0u64), Value::from(1u64)],
                &[Value::from(1u64)],
            );

            test_circ(
                &circ,
                &[Value::from(1u64), Value::from(1u64)],
                &[Value::from(2u64)],
            );

            test_circ(
                &circ,
                &[Value::from(1u64), Value::from(2u64)],
                &[Value::from(3u64)],
            );

            test_circ(
                &circ,
                &[Value::from(u64::MAX), Value::from(1u64)],
                &[Value::from(0u64)],
            );
        }
    }

    #[cfg(feature = "aes_128_reverse")]
    mod aes_128_reverse {
        use super::*;
        use aes::{Aes128, BlockEncrypt, NewBlockCipher};

        #[test]
        fn test_aes_128_reverse() {
            let circ = Circuit::load_bytes(AES_128_REVERSE).unwrap();

            let key = vec![0x00; 16];
            let m = vec![0x00; 16];
            let cipher = Aes128::new_from_slice(&key).unwrap();
            let mut ciphertext = [0x00; 16].into();
            cipher.encrypt_block(&mut ciphertext);

            ciphertext.reverse();
            test_circ(
                &circ,
                &[Value::from(key), Value::from(m)],
                &[Value::from(ciphertext.to_vec())],
            );

            let key = vec![0xFF; 16];
            let m = vec![0x00; 16];
            let cipher = Aes128::new_from_slice(&key).unwrap();
            let mut ciphertext = [0x00; 16].into();
            cipher.encrypt_block(&mut ciphertext);

            ciphertext.reverse();
            test_circ(
                &circ,
                &[Value::from(key), Value::from(m)],
                &[Value::from(ciphertext.to_vec())],
            );

            let mut key = vec![
                0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ];
            let mut pt = vec![0x00; 16];
            let cipher = Aes128::new_from_slice(&key).unwrap();
            let mut ciphertext = [0x00; 16].into();
            cipher.encrypt_block(&mut ciphertext);

            key.reverse();
            pt.reverse();
            ciphertext.reverse();
            test_circ(
                &circ,
                &[Value::from(key), Value::from(pt)],
                &[Value::from(ciphertext.to_vec())],
            );
        }
    }

    #[cfg(feature = "sha256")]
    mod sha256 {
        use super::*;
        use digest::{generic_array::GenericArray, typenum::U64};
        use sha2::compress256;

        fn partial_sha256_digest(input: &[u8], mut state: [u32; 8]) -> [u32; 8] {
            for b in input.chunks_exact(64) {
                compress256(&mut state, &[*GenericArray::<u8, U64>::from_slice(b)]);
            }
            state
        }

        #[test]
        fn test_sha256() {
            let circ = Circuit::load_bytes(SHA_256).unwrap();

            let msg = vec![0x33; 64];
            let state = [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ];
            let expected = partial_sha256_digest(&msg, state);

            let lsb_state = state
                .into_iter()
                .map(|chunk| chunk.to_le_bytes())
                .rev()
                .flatten()
                .collect();
            let lsb_expected = expected
                .into_iter()
                .map(|chunk| chunk.to_le_bytes())
                .rev()
                .flatten()
                .collect();
            test_circ(
                &circ,
                &[Value::Bytes(msg), Value::Bytes(lsb_state)],
                &[Value::Bytes(lsb_expected)],
            )
        }
    }
}
