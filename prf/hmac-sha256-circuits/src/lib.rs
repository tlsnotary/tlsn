mod hmac_sha256;
mod master_secret;
mod prf;
mod session_keys;
mod sha256;
mod verify_data;

pub use hmac_sha256::{add_hmac_sha256_finalize, add_hmac_sha256_partial, hmac_sha256_finalize};
pub use master_secret::master_secret;
pub use prf::{add_prf, prf};
pub use session_keys::session_keys;
pub use sha256::{add_sha256_compress, add_sha256_finalize, sha256};
pub use verify_data::verify_data;

#[cfg(test)]
mod test_helpers {
    use mpc_circuits::{Circuit, Value, WireGroup};

    pub fn test_circ(circ: &Circuit, inputs: &[Value], expected: &[Value]) {
        let inputs: Vec<mpc_circuits::InputValue> = inputs
            .iter()
            .zip(circ.inputs())
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
}
