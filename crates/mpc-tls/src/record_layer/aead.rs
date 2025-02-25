mod aes_gcm;
mod ghash;

pub(crate) use aes_gcm::MpcAesGcm;
use cipher::{aes::AesError, CipherError};
pub(crate) use ghash::{ComputeTags, VerifyTags};

use mpz_memory_core::{binary::U8, Array};
use mpz_vm_core::VmError;

type Nonce = Array<U8, 8>;
type Ctr = Array<U8, 4>;
type Block = Array<U8, 16>;

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub(crate) struct AeadError(ErrorRepr);

impl AeadError {
    pub(crate) fn state<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::State(err.into()))
    }

    pub(crate) fn cipher<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Cipher(err.into()))
    }

    pub(crate) fn tag<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Tag(err.into()))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("aead error: {0}")]
enum ErrorRepr {
    #[error("state error: {0}")]
    State(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("cipher error: {0}")]
    Cipher(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("tag error: {0}")]
    Tag(Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl From<VmError> for AeadError {
    fn from(err: VmError) -> Self {
        Self(ErrorRepr::Cipher(Box::new(err)))
    }
}

impl From<CipherError> for AeadError {
    fn from(err: CipherError) -> Self {
        Self(ErrorRepr::Cipher(Box::new(err)))
    }
}

impl From<AesError> for AeadError {
    fn from(err: AesError) -> Self {
        Self(ErrorRepr::Cipher(Box::new(err)))
    }
}
