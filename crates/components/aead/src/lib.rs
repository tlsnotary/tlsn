//! This crate provides implementations of 2PC AEADs for authenticated
//! encryption with a shared key.
//!
//! Both parties can work together to encrypt and decrypt messages with
//! different visibility configurations. See [`Aead`] for more information on
//! the interface.
//!
//! For example, one party can privately provide the plaintext to encrypt, while
//! both parties can see the ciphertext and the tag. Or, both parties can
//! cooperate to decrypt a ciphertext and verify the tag, while only one party
//! can see the plaintext.

//#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

// pub mod aes_gcm;
pub mod cipher;
pub use cipher::{Aes128, Cipher};

pub struct StreamCipher<C: Cipher> {
    key: C::Key,
    cipher: C,
}

impl<C: Cipher> StreamCipher<C> {
    pub fn new(key: C::Key) -> Self {
        Self {
            key,
            cipher: C::default(),
        }
    }
}

impl StreamCipher<Aes128> {}

mod mock {
    use mpz_memory_core::StaticSize;

    pub struct U8;

    impl StaticSize for U8 {
        const SIZE: usize = 1;
    }
}
