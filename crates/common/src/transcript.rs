//! TLS transcript.

use mpz_memory_core::{binary::U8, Vector};
use tls_core::msgs::enums::ContentType;

/// A transcript of sent and received TLS records.
#[derive(Debug, Default, Clone)]
pub struct TlsTranscript {
    /// Records sent by the prover.
    pub sent: Vec<Record>,
    /// Records received by the prover.
    pub recv: Vec<Record>,
}

/// A TLS record.
#[derive(Clone)]
pub struct Record {
    /// Sequence number.
    pub seq: u64,
    /// Content type.
    pub typ: ContentType,
    /// Plaintext.
    pub plaintext: Option<Vec<u8>>,
    /// VM reference to the plaintext.
    pub plaintext_ref: Option<Vector<U8>>,
    /// Explicit nonce.
    pub explicit_nonce: Vec<u8>,
    /// Ciphertext.
    pub ciphertext: Vec<u8>,
}

opaque_debug::implement!(Record);
