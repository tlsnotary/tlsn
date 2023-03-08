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

use once_cell::sync::Lazy;
use std::sync::Arc;

pub use circuit::{Circuit, CircuitId, Gate};
pub use error::{CircuitError, GroupError, ValueError};
pub use group::{Group, GroupId, GroupValue, WireGroup};
pub use input::Input;
pub use output::Output;
pub use spec::CircuitSpec;
pub use value::{BitOrder, Value, ValueType};

/// Group of wires corresponding to a circuit input
pub type InputValue = GroupValue<Input>;
/// Group of wires corresponding to a circuit output
pub type OutputValue = GroupValue<Output>;

#[cfg(feature = "aes128")]
pub static AES_128_BYTES: &'static [u8] = std::include_bytes!("../circuits/bin/aes128.bin");
#[cfg(feature = "adder64")]
pub static ADDER_64_BYTES: &'static [u8] = std::include_bytes!("../circuits/bin/adder64.bin");
#[cfg(feature = "sha256")]
pub static SHA_256_BYTES: &'static [u8] = std::include_bytes!("../circuits/bin/sha256.bin");

#[cfg(feature = "aes128")]
pub static AES_128: Lazy<Arc<Circuit>> =
    Lazy::new(|| Circuit::load_bytes(AES_128_BYTES).expect("Failed to load aes128 circuit"));
#[cfg(feature = "adder64")]
pub static ADDER_64: Lazy<Arc<Circuit>> =
    Lazy::new(|| Circuit::load_bytes(ADDER_64_BYTES).expect("Failed to load adder64 circuit"));
#[cfg(feature = "sha256")]
pub static SHA_256: Lazy<Arc<Circuit>> =
    Lazy::new(|| Circuit::load_bytes(SHA_256_BYTES).expect("Failed to load sha256 circuit"));

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
            let circ = ADDER_64.clone();

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

    #[cfg(feature = "aes128")]
    mod aes128 {
        use super::*;
        use crate::{circuits::test_circ, Value};

        use aes::{Aes128, BlockEncrypt, NewBlockCipher};

        fn reference_aes128(key: &[u8; 16], msg: &[u8; 16]) -> Vec<u8> {
            let cipher = Aes128::new(key.into());
            let mut ciphertext = [0u8; 16];
            ciphertext.copy_from_slice(msg);

            let mut ciphertext = ciphertext.into();

            cipher.encrypt_block(&mut ciphertext);

            ciphertext.to_vec()
        }

        #[test]
        fn test_aes128() {
            let circ = AES_128.clone();

            let key = [69u8; 16];
            let msg = b"aes test message";

            let expected = reference_aes128(&key, msg);

            test_circ(
                &circ,
                &[Value::Bytes(key.to_vec()), Value::Bytes(msg.to_vec())],
                &[Value::Bytes(expected)],
            );
        }
    }

    #[cfg(feature = "sha256")]
    mod sha256 {
        use super::*;
        use crate::{circuits::test_circ, Value};

        use sha2::compress256;

        static SHA256_STATE: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];

        #[test]
        fn test_sha256_compress() {
            let circ = SHA_256.clone();

            let msg = [33u8; 64];

            let mut expected = SHA256_STATE;
            compress256(&mut expected, &[msg.into()]);

            let expected = expected
                .into_iter()
                .map(|chunk| chunk.to_be_bytes())
                .flatten()
                .collect::<Vec<u8>>();

            let initial_state = SHA256_STATE
                .into_iter()
                .map(|chunk| chunk.to_be_bytes())
                .flatten()
                .collect::<Vec<u8>>();

            test_circ(
                &circ,
                &[Value::Bytes(msg.to_vec()), Value::Bytes(initial_state)],
                &[Value::Bytes(expected)],
            );
        }
    }
}
