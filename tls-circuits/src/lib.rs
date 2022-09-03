mod c1;
mod c2;
mod c3;
mod combine_pms_shares;

pub use c1::c1;
pub use c2::c2;
pub use c3::c3;
pub use combine_pms_shares::combine_pms_shares;

static SHA256_STATE: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

#[cfg(test)]
pub fn test_circ(
    circ: &mpc_circuits::Circuit,
    inputs: &[mpc_circuits::Value],
    expected: &[mpc_circuits::Value],
) {
    let inputs: Vec<mpc_circuits::InputValue> = inputs
        .iter()
        .zip(circ.inputs())
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

#[cfg(test)]
pub fn partial_sha256_digest(input: &[u8]) -> [u32; 8] {
    let mut state = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    for b in input.chunks_exact(64) {
        let block = generic_array::GenericArray::from_slice(b);
        sha2::compress256(&mut state, &[*block]);
    }
    state
}
