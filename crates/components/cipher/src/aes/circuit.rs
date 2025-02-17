use mpz_circuits::{circuits::aes128_trace, once_cell::sync::Lazy, trace, Circuit, CircuitBuilder};
use std::sync::Arc;

/// `fn(key: [u8; 16], iv: [u8; 4], nonce: [u8; 8], ctr: [u8; 4]) -> [u8; 16]`
pub(crate) static AES128_CTR: Lazy<Arc<Circuit>> = Lazy::new(|| {
    let builder = CircuitBuilder::new();

    let key = builder.add_array_input::<u8, 16>();
    let iv = builder.add_array_input::<u8, 4>();
    let nonce = builder.add_array_input::<u8, 8>();
    let ctr = builder.add_array_input::<u8, 4>();

    let keystream = aes_ctr_trace(builder.state(), key, iv, nonce, ctr);

    builder.add_output(keystream);

    Arc::new(builder.build().unwrap())
});

/// `fn(key: [u8; 16], msg: [u8; 16]) -> [u8; 16]`
pub(crate) static AES128_ECB: Lazy<Arc<Circuit>> = Lazy::new(|| {
    let builder = CircuitBuilder::new();

    let key = builder.add_array_input::<u8, 16>();
    let message = builder.add_array_input::<u8, 16>();
    let block = aes128_trace(builder.state(), key, message);

    builder.add_output(block);

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
