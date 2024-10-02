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

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

// pub mod aes_gcm;
mod cipher;
