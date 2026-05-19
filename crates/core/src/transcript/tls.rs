//! TLS transcript.

use crate::{
    connection::{CertBinding, ServerSignature, TlsVersion},
    transcript::{Direction, Transcript, tls::builder::SfHashInput},
    webpki::CertificateDer,
};

use sha2::{Digest, Sha256};

mod builder;
pub use builder::TlsTranscriptBuilder;

/// A transcript of TLS records sent and received by the prover.
///
/// # Invariants
///
/// * First record of `TlsTranscript::sent` or `TlsTranscript::recv` is the
///   finished record.
/// * Records are ordered but records which are not of type
///   [`ContentType::ApplicationData`] can be missing.
/// * Handshake related fields may be absent.
/// * Plaintext of records may be absent.
#[derive(Debug, Clone)]
pub struct TlsTranscript {
    pub(crate) time: u64,
    pub(crate) version: TlsVersion,
    pub(crate) server_signature: Option<ServerSignature>,
    pub(crate) server_cert_chain: Option<Vec<CertificateDer>>,
    pub(crate) certificate_binding: CertBinding,
    pub(crate) sent: Vec<Record>,
    pub(crate) recv: Vec<Record>,
    pub(crate) cf_hash: Option<[u8; 32]>,
    pub(crate) session_hash: Option<[u8; 32]>,
    pub(crate) sf_hash: Option<SfHashInput>,
}

impl TlsTranscript {
    /// Returns a builder for [`TlsTranscript`].
    pub fn builder<'a>() -> TlsTranscriptBuilder<'a> {
        TlsTranscriptBuilder::default()
    }

    /// Returns the start time of the connection.
    pub fn time(&self) -> u64 {
        self.time
    }

    /// Returns the TLS protocol version.
    pub fn version(&self) -> TlsVersion {
        self.version
    }

    /// Returns the signature of the server.
    pub fn server_signature(&self) -> Option<&ServerSignature> {
        self.server_signature.as_ref()
    }

    /// Returns the certificate chain.
    pub fn server_cert_chain(&self) -> Option<&[CertificateDer]> {
        self.server_cert_chain.as_deref()
    }

    /// Returns the certificate binding.
    pub fn certificate_binding(&self) -> &CertBinding {
        &self.certificate_binding
    }

    /// Returns the sent records.
    pub fn sent(&self) -> &[Record] {
        &self.sent
    }

    /// Returns the received records.
    pub fn recv(&self) -> &[Record] {
        &self.recv
    }

    /// Returns the client finished record.
    pub fn client_finished(&self) -> &Record {
        self.sent()
            .first()
            .expect("client finished record should be present")
    }

    /// Returns the client finished verify data.
    pub fn cf_vd(&self) -> Option<&[u8]> {
        let cf = self.client_finished();

        // Strips off the handshake message header.
        cf.plaintext.as_ref().and_then(|plain| plain.get(4..))
    }

    /// Returns the server finished record.
    pub fn server_finished(&self) -> &Record {
        self.recv()
            .first()
            .expect("server finished record should be present")
    }

    /// Returns the server finished verify data.
    pub fn sf_vd(&self) -> Option<&[u8]> {
        let sf = self.server_finished();

        // Strips off the handshake message header.
        sf.plaintext.as_ref().and_then(|plain| plain.get(4..))
    }

    /// Returns the client finished hash.
    pub fn cf_hash(&self) -> Option<[u8; 32]> {
        self.cf_hash.as_ref().copied()
    }

    /// Returns the session hash.
    pub fn session_hash(&self) -> Option<[u8; 32]> {
        self.session_hash.as_ref().copied()
    }

    /// Returns the server finished hash given the client finished verify
    /// data.
    pub fn sf_hash(&self, cf_vd: &[u8; 12]) -> Option<[u8; 32]> {
        let sf_hash = self.sf_hash.as_ref()?;
        let SfHashInput {
            sent_hs_bytes,
            recv_hs_bytes,
            sent_ch_end,
            recv_shd_end,
        } = sf_hash;

        let mut hasher = Sha256::new();
        hasher.update(&sent_hs_bytes[..*sent_ch_end]);
        hasher.update(&recv_hs_bytes[..*recv_shd_end]);
        hasher.update(&sent_hs_bytes[*sent_ch_end..]);

        // Append the reconstructed Client Finished handshake message.
        hasher.update([0x14, 0x00, 0x00, 0x0c]);
        hasher.update(cf_vd);
        hasher.update(&recv_hs_bytes[*recv_shd_end..]);

        let sf_hash = hasher.finalize().into();
        Some(sf_hash)
    }

    /// Returns the application data transcript.
    pub fn to_transcript(&self) -> Result<Transcript, TlsTranscriptError> {
        let mut sent = Vec::new();
        let mut recv = Vec::new();

        for record in self
            .sent
            .iter()
            .filter(|record| record.typ == ContentType::ApplicationData)
        {
            let plaintext = record
                .plaintext
                .as_ref()
                .ok_or(ErrorRepr::Incomplete {
                    direction: Direction::Sent,
                    seq: record.seq,
                })?
                .clone();
            sent.extend_from_slice(&plaintext);
        }

        for record in self
            .recv
            .iter()
            .filter(|record| record.typ == ContentType::ApplicationData)
        {
            let plaintext = record
                .plaintext
                .as_ref()
                .ok_or(ErrorRepr::Incomplete {
                    direction: Direction::Received,
                    seq: record.seq,
                })?
                .clone();
            recv.extend_from_slice(&plaintext);
        }

        Ok(Transcript::new(sent, recv))
    }
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
    /// Explicit nonce.
    pub explicit_nonce: Vec<u8>,
    /// Ciphertext.
    pub ciphertext: Vec<u8>,
    /// Tag.
    pub tag: Option<Vec<u8>>,
}

opaque_debug::implement!(Record);

/// TLS record content type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ContentType {
    /// Change cipher spec protocol.
    ChangeCipherSpec,
    /// Alert protocol.
    Alert,
    /// Handshake protocol.
    Handshake,
    /// Application data protocol.
    ApplicationData,
    /// Heartbeat protocol.
    Heartbeat,
    /// Unknown protocol.
    Unknown(u8),
}

impl From<ContentType> for tls_core::msgs::enums::ContentType {
    fn from(content_type: ContentType) -> Self {
        match content_type {
            ContentType::ChangeCipherSpec => tls_core::msgs::enums::ContentType::ChangeCipherSpec,
            ContentType::Alert => tls_core::msgs::enums::ContentType::Alert,
            ContentType::Handshake => tls_core::msgs::enums::ContentType::Handshake,
            ContentType::ApplicationData => tls_core::msgs::enums::ContentType::ApplicationData,
            ContentType::Heartbeat => tls_core::msgs::enums::ContentType::Heartbeat,
            ContentType::Unknown(id) => tls_core::msgs::enums::ContentType::Unknown(id),
        }
    }
}

impl From<tls_core::msgs::enums::ContentType> for ContentType {
    fn from(content_type: tls_core::msgs::enums::ContentType) -> Self {
        match content_type {
            tls_core::msgs::enums::ContentType::ChangeCipherSpec => ContentType::ChangeCipherSpec,
            tls_core::msgs::enums::ContentType::Alert => ContentType::Alert,
            tls_core::msgs::enums::ContentType::Handshake => ContentType::Handshake,
            tls_core::msgs::enums::ContentType::ApplicationData => ContentType::ApplicationData,
            tls_core::msgs::enums::ContentType::Heartbeat => ContentType::Heartbeat,
            tls_core::msgs::enums::ContentType::Unknown(id) => ContentType::Unknown(id),
        }
    }
}

/// Error type.
#[derive(Debug, thiserror::Error)]
#[error("TLS transcript error: {0}")]
pub struct TlsTranscriptError(#[from] ErrorRepr);

impl TlsTranscriptError {
    fn parse(msg: impl Into<String>) -> Self {
        Self(ErrorRepr::Parse(msg.into()))
    }

    fn missing(field: &'static str) -> Self {
        Self(ErrorRepr::Missing(field))
    }

    fn validation(msg: impl Into<String>) -> Self {
        Self(ErrorRepr::Validation(msg.into()))
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ErrorRepr {
    #[error("parse error: {0}")]
    Parse(String),
    #[error("missing field: {0}")]
    Missing(&'static str),
    #[error("incomplete transcript ({direction}): seq {seq}")]
    Incomplete { direction: Direction, seq: u64 },
    #[error("validation error: {0}")]
    Validation(String),
}
