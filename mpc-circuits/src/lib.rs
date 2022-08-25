pub mod builder;
pub mod circuit;
mod error;
pub mod parse;
pub mod proto;
mod spec;
pub mod utils;
mod value;

pub use circuit::{Circuit, CircuitId, Gate, Group, Input, InputValue, Output, OutputValue};
pub use error::Error;
pub use spec::CircuitSpec;
pub use value::{Value, ValueType};

#[cfg(feature = "aes_128_reverse")]
pub static AES_128_REVERSE: &'static [u8] =
    std::include_bytes!("../circuits/bin/aes_128_reverse.bin");
#[cfg(feature = "adder64")]
pub static ADDER_64: &'static [u8] = std::include_bytes!("../circuits/bin/adder64.bin");

#[cfg(test)]
mod tests {
    use crate::circuit::InputValue;

    use super::*;

    fn test_circ(circ: &Circuit, inputs: &[Value], expected: &[Value]) {
        let inputs: Vec<InputValue> = inputs
            .iter()
            .zip(circ.inputs.iter())
            .map(|(value, input)| input.to_value(value.clone()).unwrap())
            .collect();
        let outputs = circ.evaluate(&inputs).unwrap();
        for (output, expected) in outputs.iter().zip(expected) {
            if output.value() != expected {
                let report = format!(
                    "Circuit {}\n{}{}Expected: {:?}",
                    circ.name(),
                    inputs
                        .iter()
                        .enumerate()
                        .map(|(id, input)| format!("Input {}:  {:?}\n", id, input.value()))
                        .collect::<Vec<String>>()
                        .join(""),
                    format!("Output {}: {:?}\n", output.id(), output.value()),
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
}
