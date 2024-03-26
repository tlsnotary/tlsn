//! TLS session types.

use serde::{Deserialize, Serialize};

use tls_core::key::PublicKey;

use crate::{hash::Hash, serialize::CanonicalSerialize, ServerName};

/// TLS version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TlsVersion {
    /// TLS 1.2.
    V1_2 = 0x00,
    /// TLS 1.3.
    V1_3 = 0x01,
}

/// TLS session information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    /// The UNIX time when the TLS connection started.
    pub time: u64,
    /// The TLS version used in the connection.
    pub version: TlsVersion,
    /// Transcript length.
    pub transcript_length: TranscriptLength,
    /// The server's ephemeral public key used in the TLS handshake.
    pub server_ephemeral_key: PublicKey,
}

impl CanonicalSerialize for ConnectionInfo {
    #[inline]
    fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.time.to_le_bytes());
        bytes.push(self.version as u8);
        bytes.extend_from_slice(&self.transcript_length.sent.to_le_bytes());
        bytes.extend_from_slice(&self.transcript_length.received.to_le_bytes());
        bytes.extend_from_slice(&self.server_ephemeral_key.group.get_u16().to_le_bytes());
        bytes.extend_from_slice(&self.server_ephemeral_key.key);
        bytes
    }
}

/// Transcript length information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptLength {
    /// The number of bytes sent by the Prover to the Server.
    pub sent: u32,
    /// The number of bytes received by the Prover from the Server.
    pub received: u32,
}

/// TLS handshake data.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HandshakeData(tls_core::handshake::HandshakeData);

/// TLS handshake proof.
pub struct HandshakeProof {
    data: HandshakeData,
    /// The nonce which was hashed with the handshake data.
    nonce: [u8; 32],
}

#[derive(Debug)]
pub enum HandshakeProofError {}

impl HandshakeProof {
    /// Verifies the handshake proof.
    ///
    /// # Arguments
    ///
    /// * `commitment` - The commitment to the handshake data.
    /// * `time` - The UNIX time when the TLS connection started.
    /// * `server_name` - The server's name.
    pub fn verify(
        &self,
        commitment: &Hash,
        time: u64,
        server_name: &ServerName,
    ) -> Result<(), HandshakeProofError> {
        todo!()
    }
}
