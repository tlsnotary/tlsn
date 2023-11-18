use std::sync::Arc;

use mpz_circuits::{
    types::{StaticValueType, Value},
    Circuit,
};

use crate::circuit::AES_CTR;

/// A counter-mode block cipher circuit.
pub trait CtrCircuit: Default + Clone + Send + Sync + 'static {
    /// The key type
    type KEY: StaticValueType + Send + Sync + 'static;
    /// The block type
    type BLOCK: StaticValueType
        + TryFrom<Vec<u8>>
        + TryFrom<Value>
        + Into<Vec<u8>>
        + Default
        + Send
        + Sync
        + 'static;
    /// The IV type
    type IV: StaticValueType
        + TryFrom<Vec<u8>>
        + TryFrom<Value>
        + Into<Vec<u8>>
        + Send
        + Sync
        + 'static;
    /// The nonce type
    type NONCE: StaticValueType
        + TryFrom<Vec<u8>>
        + TryFrom<Value>
        + Into<Vec<u8>>
        + Clone
        + Copy
        + Send
        + Sync
        + std::fmt::Debug
        + 'static;

    /// The length of the key
    const KEY_LEN: usize;
    /// The length of the block
    const BLOCK_LEN: usize;
    /// The length of the IV
    const IV_LEN: usize;
    /// The length of the nonce
    const NONCE_LEN: usize;

    /// Returns the circuit of the cipher
    fn circuit() -> Arc<Circuit>;

    /// Applies the keystream to the message
    fn apply_keystream(
        key: &Self::KEY,
        iv: &Self::IV,
        start_ctr: usize,
        explicit_nonce: &Self::NONCE,
        msg: &[u8],
    ) -> Vec<u8>;
}

/// A circuit for AES-128 in counter mode.
#[derive(Default, Debug, Clone)]
pub struct Aes128Ctr;

impl CtrCircuit for Aes128Ctr {
    type KEY = [u8; 16];
    type BLOCK = [u8; 16];
    type IV = [u8; 4];
    type NONCE = [u8; 8];

    const KEY_LEN: usize = 16;
    const BLOCK_LEN: usize = 16;
    const IV_LEN: usize = 4;
    const NONCE_LEN: usize = 8;

    fn circuit() -> Arc<Circuit> {
        AES_CTR.clone()
    }

    fn apply_keystream(
        key: &Self::KEY,
        iv: &Self::IV,
        start_ctr: usize,
        explicit_nonce: &Self::NONCE,
        msg: &[u8],
    ) -> Vec<u8> {
        use ::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
        use aes::Aes128;
        use ctr::Ctr32BE;

        let mut full_iv = [0u8; 16];
        full_iv[0..4].copy_from_slice(iv);
        full_iv[4..12].copy_from_slice(explicit_nonce);
        let mut cipher = Ctr32BE::<Aes128>::new(key.into(), &full_iv.into());
        let mut buf = msg.to_vec();

        cipher
            .try_seek(start_ctr * Self::BLOCK_LEN)
            .expect("start counter is less than keystream length");
        cipher.apply_keystream(&mut buf);

        buf
    }
}
