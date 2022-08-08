pub mod circuit;
mod error;
pub mod parse;
pub mod proto;

pub use circuit::{Circuit, CircuitId, Gate, Group, Input, InputValue, Output, OutputValue};
pub use error::Error;

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

    fn test_circ(circ: &Circuit, inputs: &[Vec<bool>], expected: &[Vec<bool>]) {
        let inputs: Vec<InputValue> = inputs
            .iter()
            .zip(circ.inputs.iter())
            .map(|(value, input)| input.to_value(value).unwrap())
            .collect();
        let outputs = circ.evaluate(&inputs).unwrap();
        for (output, expected) in outputs.iter().zip(expected) {
            if output.as_ref() != expected {
                let report = format!(
                    "Circuit {}\n{}{}Expected: {}",
                    circ.name(),
                    inputs
                        .iter()
                        .enumerate()
                        .map(|(id, input)| format!(
                            "Input {}:  {}\n",
                            id,
                            boolvec_to_string(input.as_ref())
                        ))
                        .collect::<Vec<String>>()
                        .join(""),
                    format!(
                        "Output {}: {}\n",
                        output.id(),
                        boolvec_to_string(output.as_ref())
                    ),
                    boolvec_to_string(expected)
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

            let a = vec![false; 64];
            let b = vec![false; 64];
            let c = vec![false; 64];
            test_circ(&circ, &[a, b], &[c]);

            let mut a = vec![false; 64];
            a[0] = true;
            let b = vec![false; 64];
            let mut c = vec![false; 64];
            c[0] = true;
            test_circ(&circ, &[a, b], &[c]);

            let mut a = vec![false; 64];
            a[0] = true;
            let mut b = vec![false; 64];
            b[0] = true;
            let mut c = vec![false; 64];
            c[1] = true;
            test_circ(&circ, &[a, b], &[c]);

            let mut a = vec![false; 64];
            a[63] = true;
            let mut b = vec![false; 64];
            b[63] = true;
            let c = vec![false; 64];
            test_circ(&circ, &[a, b], &[c]);
        }
    }

    #[cfg(feature = "aes_128_reverse")]
    mod aes_128_reverse {
        use super::*;

        #[test]
        fn test_aes_128_reverse() {
            let circ = Circuit::load_bytes(AES_128_REVERSE).unwrap();

            let key = vec![false; 128];
            let pt = vec![false; 128];
            let mut ct = string_to_boolvec("01100110111010010100101111010100111011111000101000101100001110111000100001001100111110100101100111001010001101000010101100101110");
            ct.reverse();
            test_circ(&circ, &[key, pt], &[ct]);

            let key = vec![true; 128];
            let pt = vec![false; 128];
            let mut ct = string_to_boolvec("10100001111101100010010110001100100001110111110101011111110011011000100101100100010010000100010100111000101111111100100100101100");
            ct.reverse();
            test_circ(&circ, &[key, pt], &[ct]);

            let mut key = vec![false; 128];
            key[120] = true;
            let pt = vec![false; 128];
            let mut ct = string_to_boolvec("11011100000011101101100001011101111110010110000100011010101110110111001001001001110011011101000101101000110001010100011001111110");
            ct.reverse();
            test_circ(&circ, &[key, pt], &[ct]);
        }
    }
}
