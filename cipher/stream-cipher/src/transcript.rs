use futures::Sink;
use mpc_garble_core::Label;

pub type TranscriptSink = Box<dyn Sink<MessageTranscript, Error = std::io::Error> + Send + Unpin>;

#[derive(Clone)]
pub struct MessageTranscript {
    explicit_nonce: Vec<u8>,
    plaintext: Vec<u8>,
    plaintext_labels: Vec<Label>,
    ciphertext: Vec<u8>,
}

impl MessageTranscript {
    pub fn new(
        explicit_nonce: Vec<u8>,
        plaintext: Vec<u8>,
        plaintext_labels: Vec<Label>,
        ciphertext: Vec<u8>,
    ) -> Self {
        Self {
            explicit_nonce,
            plaintext,
            plaintext_labels,
            ciphertext,
        }
    }

    pub fn get_explicit_nonce(&self) -> &[u8] {
        &self.explicit_nonce
    }

    pub fn get_plaintext(&self) -> &[u8] {
        &self.plaintext
    }

    pub fn get_plaintext_labels(&self) -> &[Label] {
        &self.plaintext_labels
    }

    pub fn get_ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}
