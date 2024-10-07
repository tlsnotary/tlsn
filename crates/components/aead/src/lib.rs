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

pub mod aes_gcm;
pub mod cipher;
pub mod config;

use mpz_common::Context;
use mpz_memory_core::{Array, Vector};
use mpz_vm_core::VmExt;
use tlsn_universal_hash::UniversalHash;

pub trait AeadCipher<Ctx: Context, Vm: VmExt> {
    /// The error type for the AEAD.
    type Error: std::error::Error + Send + Sync + 'static;
}
