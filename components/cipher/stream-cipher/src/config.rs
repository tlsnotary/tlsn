use derive_builder::Builder;
use std::fmt::Debug;

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

#[derive(Debug, Clone, Copy)]
pub(crate) enum ExecutionMode {
    Mpc,
    Prove,
    Verify,
}

pub(crate) fn is_valid_mode(mode: &ExecutionMode, input_text: &InputText) -> bool {
    match (mode, input_text) {
        (ExecutionMode::Mpc, _) => true,
        (ExecutionMode::Prove, InputText::Private { .. }) => true,
        (ExecutionMode::Verify, InputText::Blind { .. }) => true,
        _ => false,
    }
}
