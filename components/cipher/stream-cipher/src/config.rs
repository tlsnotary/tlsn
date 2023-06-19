use std::marker::PhantomData;

use derive_builder::Builder;
use mpz_garble::ValueRef;
use std::fmt::Debug;

use crate::{input::InputText, CtrCircuit};

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

#[derive(Debug)]
pub(crate) struct KeyBlockConfig<C: CtrCircuit> {
    pub(crate) key: ValueRef,
    pub(crate) iv: ValueRef,
    pub(crate) explicit_nonce: C::NONCE,
    pub(crate) ctr: u32,
    pub(crate) input_text_config: InputText,
    pub(crate) output_text_config: OutputTextConfig,
    _pd: PhantomData<C>,
}

impl<C: CtrCircuit> KeyBlockConfig<C> {
    pub(crate) fn new(
        key: ValueRef,
        iv: ValueRef,
        explicit_nonce: C::NONCE,
        ctr: u32,
        input_text_config: InputText,
        output_text_config: OutputTextConfig,
    ) -> Self {
        Self {
            key,
            iv,
            explicit_nonce,
            ctr,
            input_text_config,
            output_text_config,
            _pd: PhantomData,
        }
    }
}

#[derive(Debug)]
pub(crate) enum OutputTextConfig {
    Public { ids: Vec<String> },
    Private { ids: Vec<String> },
    Blind { ids: Vec<String> },
    Shared { ids: Vec<String> },
}

impl OutputTextConfig {
    /// Appends padding bytes to the output text.
    pub(crate) fn append_padding(&mut self, append_ids: Vec<String>) {
        match self {
            OutputTextConfig::Public { ids } => {
                ids.extend(append_ids);
            }
            OutputTextConfig::Private { ids } => {
                ids.extend(append_ids);
            }
            OutputTextConfig::Blind { ids } => {
                ids.extend(append_ids);
            }
            OutputTextConfig::Shared { ids } => {
                ids.extend(append_ids);
            }
        };
    }

    /// Drains the first `n` bytes from the output text.
    pub(crate) fn drain(&mut self, n: usize) -> OutputTextConfig {
        match self {
            OutputTextConfig::Public { ids } => OutputTextConfig::Public {
                ids: ids.drain(..n).collect(),
            },
            OutputTextConfig::Private { ids } => OutputTextConfig::Private {
                ids: ids.drain(..n).collect(),
            },
            OutputTextConfig::Blind { ids } => OutputTextConfig::Blind {
                ids: ids.drain(..n).collect(),
            },
            OutputTextConfig::Shared { ids } => OutputTextConfig::Shared {
                ids: ids.drain(..n).collect(),
            },
        }
    }
}
