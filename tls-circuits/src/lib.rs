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
    use std::slice::from_ref;

    use generic_array::typenum::U64;
    use sha2::{
        compress256,
        digest::block_buffer::{BlockBuffer, Eager},
    };

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

    pub fn finalize_sha256_digest(mut state: [u32; 8], pos: usize, input: &[u8]) -> [u8; 32] {
        let mut buffer = BlockBuffer::<U64, Eager>::default();
        buffer.digest_blocks(input, |b| compress256(&mut state, b));
        buffer.digest_pad(
            0x80,
            &(((input.len() + pos) * 8) as u64).to_be_bytes(),
            |b| compress256(&mut state, from_ref(b)),
        );

        let mut out: [u8; 32] = [0; 32];
        for (chunk, v) in out.chunks_exact_mut(4).zip(state.iter()) {
            chunk.copy_from_slice(&v.to_be_bytes());
        }
        out
    }
}
