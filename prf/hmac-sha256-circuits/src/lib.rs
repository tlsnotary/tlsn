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

static SHA256_STATE: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

#[cfg(test)]
mod test_helpers {
    use hmac::{Hmac, Mac};

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

    pub fn partial_hmac(key: &[u8]) -> ([u32; 8], [u32; 8]) {
        let mut key_opad = [0x5cu8; 64];
        let mut key_ipad = [0x36u8; 64];

        key_opad.iter_mut().zip(key).for_each(|(a, b)| *a ^= b);
        key_ipad.iter_mut().zip(key).for_each(|(a, b)| *a ^= b);

        let outer_state = partial_sha256_digest(&key_opad);
        let inner_state = partial_sha256_digest(&key_ipad);

        (outer_state, inner_state)
    }

    pub fn hmac(key: &[u8], msg: &[u8]) -> Vec<u8> {
        let mut hmac = Hmac::<sha2::Sha256>::new_from_slice(key).unwrap();
        hmac.update(msg);
        hmac.finalize().into_bytes().to_vec()
    }

    pub fn prf_a(key: &[u8], seed: &[u8], i: usize) -> Vec<u8> {
        (0..i).fold(seed.to_vec(), |a_prev, _| hmac(key, &a_prev))
    }

    fn prf_p_hash(key: &[u8], seed: &[u8], iterations: usize) -> Vec<u8> {
        (0..iterations)
            .map(|i| {
                let msg = {
                    let mut msg = prf_a(key, seed, i + 1);
                    msg.extend_from_slice(seed);
                    msg
                };
                hmac(key, &msg)
            })
            .flatten()
            .collect()
    }

    pub fn prf(key: &[u8], label: &[u8], seed: &[u8], bytes: usize) -> Vec<u8> {
        let iterations = bytes / 32 + (bytes % 32 != 0) as usize;

        let mut label_seed = label.to_vec();
        label_seed.extend_from_slice(seed);

        prf_p_hash(key, &label_seed, iterations)[..bytes].to_vec()
    }
}
