//! TLS transcript.

use crate::{
    connection::{
        Certificate, ConnectionInfo, HandshakeData, HandshakeDataV1_2, ServerCertData,
        ServerEphemKey, ServerSignature, TlsVersion, VerifyData,
    },
    transcript::{Direction, Transcript},
};
use tls_core::msgs::enums::ContentType;

/// A transcript of TLS records sent and received by the prover.
#[derive(Debug, Clone)]
pub struct TlsTranscript {
    time: u64,
    version: TlsVersion,
    server_cert_chain: Option<Vec<Certificate>>,
    server_signature: Option<ServerSignature>,
    handshake_data: HandshakeData,
    verify_data: VerifyData,
    sent: Vec<Record>,
    recv: Vec<Record>,
}

impl TlsTranscript {
    /// Creates a new TLS transcript.
    pub fn new(
        time: u64,
        version: TlsVersion,
        server_certs: Option<Vec<Certificate>>,
        server_signature: Option<ServerSignature>,
        handshake_data: HandshakeData,
        verify_data: VerifyData,
        sent: Vec<Record>,
        recv: Vec<Record>,
    ) -> Result<Self, TlsTranscriptError> {
        todo!()
    }

    /// Returns the start time of the connection.
    pub fn time(&self) -> u64 {
        self.time
    }

    /// Returns the TLS protocol version.
    pub fn version(&self) -> &TlsVersion {
        &self.version
    }

    /// Returns the server certificate chain.
    pub fn server_cert_chain(&self) -> Option<&[Certificate]> {
        self.server_cert_chain.as_ref().map(Vec::as_slice)
    }

    /// Returns the server signature.
    pub fn server_signature(&self) -> Option<&ServerSignature> {
        self.server_signature.as_ref()
    }

    /// Returns the server ephemeral key used in the TLS handshake.
    pub fn server_ephemeral_key(&self) -> &ServerEphemKey {
        match &self.handshake_data {
            HandshakeData::V1_2(HandshakeDataV1_2 {
                server_ephemeral_key,
                ..
            }) => server_ephemeral_key,
        }
    }

    /// Returns the handshake data.
    pub fn handshake_data(&self) -> &HandshakeData {
        &self.handshake_data
    }

    /// Returns the handshake verify data.
    pub fn verify_data(&self) -> &VerifyData {
        &self.verify_data
    }

    /// Returns the sent records.
    pub fn sent(&self) -> &[Record] {
        &self.sent
    }

    /// Returns the received records.
    pub fn recv(&self) -> &[Record] {
        &self.recv
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
                .ok_or(ErrorRepr::IncompleteTranscript {
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
                .ok_or(ErrorRepr::IncompleteTranscript {
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

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct TlsTranscriptError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("record is missing application data plaintext ({direction}): sequence number {seq}")]
    IncompleteTranscript { direction: Direction, seq: u64 },
}
