mod full_adder;
mod half_adder;
mod nbit_adder;

pub use full_adder::full_adder;
pub use half_adder::half_adder;
pub use nbit_adder::nbit_adder;

pub fn test_circ(circ: &crate::Circuit, inputs: &[crate::Value], expected: &[crate::Value]) {
    let inputs: Vec<crate::InputValue> = inputs
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
