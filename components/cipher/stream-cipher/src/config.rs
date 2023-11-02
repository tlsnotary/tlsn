use std::marker::PhantomData;

use derive_builder::Builder;
use mpz_garble::value::ValueRef;
use std::fmt::Debug;

use crate::CtrCircuit;

/// Configuration for a stream cipher.
#[derive(Debug, Clone, Builder)]
pub struct StreamCipherConfig {
    /// The ID of the stream cipher.
    #[builder(setter(into))]
    pub(crate) id: String,
    /// The start block counter value.
    #[builder(default = "2")]
    pub(crate) start_ctr: usize,
    /// Transcript ID used to determine the unique identifiers
    /// for the plaintext bytes during encryption and decryption.
    #[builder(setter(into), default = "\"transcript\".to_string()")]
    pub(crate) transcript_id: String,
}

impl StreamCipherConfig {
    /// Creates a new builder for the stream cipher configuration.
    pub fn builder() -> StreamCipherConfigBuilder {
        StreamCipherConfigBuilder::default()
    }
}

pub(crate) struct KeyBlockConfig<C: CtrCircuit> {
    pub(crate) key: ValueRef,
    pub(crate) iv: ValueRef,
    pub(crate) explicit_nonce: C::NONCE,
    pub(crate) ctr: u32,
    _pd: PhantomData<C>,
}

impl<C: CtrCircuit> Debug for KeyBlockConfig<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyBlockConfig")
            .field("key", &self.key)
            .field("iv", &self.iv)
            .field("explicit_nonce", &self.explicit_nonce)
            .field("ctr", &self.ctr)
            .finish()
    }
}

impl<C: CtrCircuit> KeyBlockConfig<C> {
    pub(crate) fn new(key: ValueRef, iv: ValueRef, explicit_nonce: C::NONCE, ctr: u32) -> Self {
        Self {
            key,
            iv,
            explicit_nonce,
            ctr,
            _pd: PhantomData,
        }
    }
}

pub(crate) enum InputText {
    Public { ids: Vec<String>, text: Vec<u8> },
    Private { ids: Vec<String>, text: Vec<u8> },
    Blind { ids: Vec<String> },
}

impl std::fmt::Debug for InputText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Public { ids, .. } => f
                .debug_struct("Public")
                .field("ids", ids)
                .field("text", &"{{ ... }}")
                .finish(),
            Self::Private { ids, .. } => f
                .debug_struct("Private")
                .field("ids", ids)
                .field("text", &"{{ ... }}")
                .finish(),
            Self::Blind { ids, .. } => f.debug_struct("Blind").field("ids", ids).finish(),
        }
    }
}
