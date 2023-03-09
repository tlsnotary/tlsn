mod c1;
mod c2;
mod c3;
mod c4;
mod c5;
mod c6;
mod c7;
mod combine_pms_shares;

pub use c1::c1;
pub use c2::c2;
pub use c3::c3;
pub use c4::c4;
pub use c5::c5;
pub use c6::c6;
pub use c7::c7;
pub use combine_pms_shares::combine_pms_shares;

static SHA256_STATE: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

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
