mod combine_pms_shares;
mod hmac_pad;
mod hmac_sha256;
mod hmac_sha256_finalize;
mod master_secret;
mod premaster_secret;
mod prf;
mod session_keys;
mod sha256;
mod sha256_finalize;
mod verify_data;

pub use combine_pms_shares::combine_pms_shares;
pub use hmac_pad::hmac_pad;
pub use hmac_sha256_finalize::hmac_sha256_finalize;
pub use master_secret::master_secret;
pub use premaster_secret::premaster_secret;
pub use session_keys::session_keys;
pub use sha256::sha256;
pub use sha256_finalize::sha256_finalize;
pub use verify_data::verify_data;

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

    pub fn partial_sha256_digest(input: &[u8]) -> [u32; 8] {
        let mut state = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];
        for b in input.chunks(64) {
            let mut block = [0u8; 64];
            block[..b.len()].copy_from_slice(b);
            sha2::compress256(&mut state, &[block.into()]);
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
