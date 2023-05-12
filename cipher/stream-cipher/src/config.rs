use std::marker::PhantomData;

use derive_builder::Builder;
use mpc_garble::ValueRef;

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
    pub(crate) input_text_config: InputTextConfig,
    pub(crate) output_text_config: OutputTextConfig,
    _pd: PhantomData<C>,
}

impl<C: CtrCircuit> KeyBlockConfig<C> {
    pub(crate) fn new(
        key: ValueRef,
        iv: ValueRef,
        explicit_nonce: C::NONCE,
        ctr: u32,
        input_text_config: InputTextConfig,
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

pub(crate) enum InputTextConfig {
    Public { ids: Vec<String>, text: Vec<u8> },
    Private { ids: Vec<String>, text: Vec<u8> },
    Blind { ids: Vec<String> },
}

impl InputTextConfig {
    /// Returns the length of the input text.
    #[allow(clippy::len_without_is_empty)]
    pub(crate) fn len(&self) -> usize {
        match self {
            InputTextConfig::Public { text, .. } => text.len(),
            InputTextConfig::Private { text, .. } => text.len(),
            InputTextConfig::Blind { ids } => ids.len(),
        }
    }

    /// Appends padding bytes to the input text.
    pub(crate) fn append_padding(&mut self, append_ids: Vec<String>) {
        match self {
            InputTextConfig::Public { ids, text } => {
                ids.extend(append_ids);
                text.resize(ids.len(), 0u8);
            }
            InputTextConfig::Private { ids, text } => {
                ids.extend(append_ids);
                text.resize(ids.len(), 0u8);
            }
            InputTextConfig::Blind { ids } => {
                ids.extend(append_ids);
            }
        };
    }

    /// Drains the first `n` bytes from the input text.
    pub(crate) fn drain(&mut self, n: usize) -> InputTextConfig {
        match self {
            InputTextConfig::Public { ids, text } => InputTextConfig::Public {
                ids: ids.drain(..n).collect(),
                text: text.drain(..n).collect(),
            },
            InputTextConfig::Private { ids, text: bytes } => InputTextConfig::Private {
                ids: ids.drain(..n).collect(),
                text: bytes.drain(..n).collect(),
            },
            InputTextConfig::Blind { ids } => InputTextConfig::Blind {
                ids: ids.drain(..n).collect(),
            },
        }
    }
}

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
