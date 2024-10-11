use crate::cipher::Cipher;
use mpz_circuits::{
    circuits::aes128_trace, once_cell::sync::Lazy, Circuit, CircuitBuilder, Tracer,
};
use mpz_memory_core::{binary::U8, Array};
use std::sync::Arc;

/// A circuit for AES-128.
#[derive(Default, Debug, Clone, Copy)]
pub struct Aes128;

impl Cipher for Aes128 {
    type Key = Array<U8, 16>;
    type Iv = Array<U8, 4>;
    type Block = Array<U8, 16>;

    fn ecb_shared() -> Arc<Circuit> {
        AES128_ECB_SHARED.clone()
    }

    fn ctr() -> Arc<Circuit> {
        AES128_CTR.clone()
    }

    fn ctr_masked() -> Arc<Circuit> {
        AES128_CTR_MASKED.clone()
    }

    fn otp() -> Arc<Circuit> {
        let builder = CircuitBuilder::new();

        let key = builder.add_array_input::<u8, 16>();
        let otp = builder.add_array_input::<u8, 16>();

        let output = key
            .into_iter()
            .zip(otp)
            .map(|(key, otp)| key ^ otp)
            .collect::<Vec<_>>();
        builder.add_output(output);

        Arc::new(builder.build().unwrap())
    }
}

/// `fn(key: [u8; 16], block: [u8; 16], message: [u8; 16]) -> [u8; 16]`
static AES128_CTR: Lazy<Arc<Circuit>> = Lazy::new(|| {
    let builder = CircuitBuilder::new();

    let key = builder.add_array_input::<u8, 16>();
    let block = builder.add_array_input::<u8, 16>();
    let keystream = aes128_trace(builder.state(), key, block);

    let message = builder.add_array_input::<u8, 16>();
    let output = keystream
        .into_iter()
        .zip(message)
        .map(|(a, b)| a ^ b)
        .collect::<Vec<_>>();
    builder.add_output(output);

    Arc::new(builder.build().unwrap())
});

/// `fn(key: [u8; 16], block: [u8; 16], message: [u8; 16], otp: [u8; 16]) -> [u8; 16]`
static AES128_CTR_MASKED: Lazy<Arc<Circuit>> = Lazy::new(|| {
    let builder = CircuitBuilder::new();

    let key = builder.add_array_input::<u8, 16>();
    let block = builder.add_array_input::<u8, 16>();
    let keystream = aes128_trace(builder.state(), key, block);

    let message = builder.add_array_input::<u8, 16>();
    let otp = builder.add_array_input::<u8, 16>();
    let output = keystream
        .into_iter()
        .zip(message)
        .zip(otp)
        .map(|((ks, msg), otp)| ks ^ msg ^ otp)
        .collect::<Vec<_>>();
    builder.add_output(output);

    Arc::new(builder.build().unwrap())
});

/// `fn(key: [u8; 16], msg: [u8; 16], otp_0: [u8; 16], otp_1: [u8; 16]) -> [u8; 16]`
static AES128_ECB_SHARED: Lazy<Arc<Circuit>> = Lazy::new(|| {
    let builder = CircuitBuilder::new();

    let key = builder.add_array_input::<u8, 16>();
    let message = builder.add_array_input::<u8, 16>();
    let aes_block = aes128_trace(builder.state(), key, message);

    let otp_0 = builder.add_array_input::<u8, 16>();
    let otp_1 = builder.add_array_input::<u8, 16>();

    let output = aes_block
        .into_iter()
        .zip(otp_0)
        .zip(otp_1)
        .map(|((block, otp_0), otp_1)| block ^ otp_0 ^ otp_1)
        .collect::<Vec<_>>();
    builder.add_output(output);

    Arc::new(builder.build().unwrap())
});
