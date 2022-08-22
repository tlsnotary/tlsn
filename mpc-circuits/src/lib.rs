pub mod circuit;
mod error;
pub mod parse;
pub mod proto;
mod value;

pub use circuit::{Circuit, CircuitId, Gate, Group, Input, InputValue, Output, OutputValue};
pub use error::Error;
pub use value::{Value, ValueType};

#[cfg(feature = "aes_128_reverse")]
pub static AES_128_REVERSE: &'static [u8] = std::include_bytes!("../circuits/aes_128_reverse.bin");
#[cfg(feature = "adder64")]
pub static ADDER_64: &'static [u8] = std::include_bytes!("../circuits/adder64.bin");

#[cfg(test)]
mod tests {
    use crate::circuit::InputValue;

    use super::*;

    fn boolvec_to_string(v: &[bool]) -> String {
        v.iter().map(|b| (*b as u8).to_string()).collect::<String>()
    }

    fn string_to_boolvec(s: &str) -> Vec<bool> {
        s.chars().map(|char| char == '1').collect()
    }

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
                &[Value::from(u64::MAX), Value::from(u64::MAX)],
                &[Value::from(0u64)],
            );
        }
    }

    #[cfg(feature = "aes_128_reverse")]
    mod aes_128_reverse {
        use super::*;

        #[test]
        fn test_aes_128_reverse() {
            let circ = Circuit::load_bytes(AES_128_REVERSE).unwrap();

            test_circ(
                &circ,
                &[Value::from(0u128), Value::from(0u128)],
                &[Value::from(136792598789324718765670228683992083246u128)],
            );

            test_circ(
                &circ,
                &[Value::from(u128::MAX), Value::from(0u128)],
                &[Value::from(215283773931601154712576325941020576044u128)],
            );

            // let mut key = vec![false; 128];
            // key[120] = true;
            // let pt = vec![false; 128];
            // let mut ct = string_to_boolvec("11011100000011101101100001011101111110010110000100011010101110110111001001001001110011011101000101101000110001010100011001111110");
            // ct.reverse();
            // test_circ(&circ, &[key, pt], &[ct]);
        }
    }
}
