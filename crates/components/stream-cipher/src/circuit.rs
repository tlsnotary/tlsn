use mpz_circuits::{circuits::aes128_trace, once_cell::sync::Lazy, trace, Circuit, CircuitBuilder};
use std::sync::Arc;

/// AES encrypts a counter block.
///
/// # Inputs
///
///   0. KEY: 16-byte encryption key
///   1. IV: 4-byte IV
///   2. EXPLICIT_NONCE: 8-byte explicit nonce
///   3. CTR: 4-byte counter
///
/// # Outputs
///
///   0. ECB: 16-byte output
pub(crate) static AES_CTR: Lazy<Arc<Circuit>> = Lazy::new(|| {
    let builder = CircuitBuilder::new();
    let key = builder.add_array_input::<u8, 16>();
    let iv = builder.add_array_input::<u8, 4>();
    let nonce = builder.add_array_input::<u8, 8>();
    let ctr = builder.add_array_input::<u8, 4>();
    let ecb = aes_ctr_trace(builder.state(), key, iv, nonce, ctr);
    builder.add_output(ecb);

    Arc::new(builder.build().unwrap())
});

#[trace]
#[dep(aes_128, aes128_trace)]
#[allow(dead_code)]
fn aes_ctr(key: [u8; 16], iv: [u8; 4], explicit_nonce: [u8; 8], ctr: [u8; 4]) -> [u8; 16] {
    let block: Vec<_> = iv.into_iter().chain(explicit_nonce).chain(ctr).collect();
    aes_128(key, block.try_into().unwrap())
}

#[allow(dead_code)]
fn aes_128(key: [u8; 16], msg: [u8; 16]) -> [u8; 16] {
    use aes::{
        cipher::{BlockEncrypt, KeyInit},
        Aes128,
    };

    let aes = Aes128::new_from_slice(&key).unwrap();
    let mut ciphertext = msg.into();
    aes.encrypt_block(&mut ciphertext);
    ciphertext.into()
}

/// Builds a circuit for computing the XOR of two arrays.
pub(crate) fn build_array_xor(len: usize) -> Arc<Circuit> {
    let builder = CircuitBuilder::new();
    let a = builder.add_vec_input::<u8>(len);
    let b = builder.add_vec_input::<u8>(len);
    let c = a.into_iter().zip(b).map(|(a, b)| a ^ b).collect::<Vec<_>>();
    builder.add_output(c);
    Arc::new(builder.build().expect("circuit is valid"))
}
