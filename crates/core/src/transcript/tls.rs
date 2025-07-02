//! TLS transcript.

use crate::{
    connection::{
        Certificate, HandshakeData, HandshakeDataV1_2, ServerEphemKey, ServerSignature, TlsVersion,
        VerifyData,
    },
    transcript::{Direction, Transcript},
};
use tls_core::msgs::{
    alert::AlertMessagePayload,
    codec::{Codec, Reader},
    enums::{AlertDescription, ContentType, ProtocolVersion},
    handshake::{HandshakeMessagePayload, HandshakePayload},
};

/// A transcript of TLS records sent and received by the prover.
#[derive(Debug, Clone)]
pub struct TlsTranscript {
    time: u64,
    version: TlsVersion,
    server_cert_chain: Option<Vec<Certificate>>,
    server_signature: Option<ServerSignature>,
    handshake_data: HandshakeData,
    sent: Vec<Record>,
    recv: Vec<Record>,
}

impl TlsTranscript {
    /// Creates a new TLS transcript.
    pub fn new(
        time: u64,
        version: TlsVersion,
        server_cert_chain: Option<Vec<Certificate>>,
        server_signature: Option<ServerSignature>,
        handshake_data: HandshakeData,
        verify_data: VerifyData,
        sent: Vec<Record>,
        recv: Vec<Record>,
    ) -> Result<Self, TlsTranscriptError> {
        let mut sent_iter = sent.iter();
        let mut recv_iter = recv.iter();

        // Make sure the client finished verify data message was sent first.
        if let Some(record) = sent_iter.next() {
            let payload = record
                .plaintext
                .as_ref()
                .ok_or(TlsTranscriptError::validation(
                    "client finished message was hidden from the follower",
                ))?;

            let mut reader = Reader::init(payload);
            let payload =
                HandshakeMessagePayload::read_version(&mut reader, ProtocolVersion::TLSv1_2)
                    .ok_or(TlsTranscriptError::validation(
                        "first record sent was not a handshake message",
                    ))?;

            let HandshakePayload::Finished(vd) = payload.payload else {
                return Err(TlsTranscriptError::validation(
                    "first record sent was not a client finished message",
                ));
            };

            if vd.0 != verify_data.client_finished {
                return Err(TlsTranscriptError::validation(
                    "inconsistent client finished verify data",
                ));
            }
        } else {
            return Err(TlsTranscriptError::validation(
                "client finished was not sent",
            ));
        }

        // Make sure the server finished verify data message was received first.
        if let Some(record) = recv_iter.next() {
            let payload = record
                .plaintext
                .as_ref()
                .ok_or(TlsTranscriptError::validation(
                    "server finished message was hidden from the follower",
                ))?;

            let mut reader = Reader::init(payload);
            let payload =
                HandshakeMessagePayload::read_version(&mut reader, ProtocolVersion::TLSv1_2)
                    .ok_or(TlsTranscriptError::validation(
                        "first record received was not a handshake message",
                    ))?;

            let HandshakePayload::Finished(vd) = payload.payload else {
                return Err(TlsTranscriptError::validation(
                    "first record received was not a server finished message",
                ));
            };

            if vd.0 != verify_data.server_finished {
                return Err(TlsTranscriptError::validation(
                    "inconsistent server finished verify data",
                ));
            }
        } else {
            return Err(TlsTranscriptError::validation(
                "server finished was not received",
            ));
        }

        // Verify last record sent was either application data or close notify.
        if let Some(record) = sent_iter.next_back() {
            match record.typ {
                ContentType::ApplicationData => {}
                ContentType::Alert => {
                    // Ensure the alert is a close notify.
                    let payload =
                        record
                            .plaintext
                            .as_ref()
                            .ok_or(TlsTranscriptError::validation(
                                "alert content was hidden from the follower",
                            ))?;

                    let mut reader = Reader::init(payload);
                    let payload = AlertMessagePayload::read(&mut reader).ok_or(
                        TlsTranscriptError::validation("alert message was malformed"),
                    )?;

                    let AlertDescription::CloseNotify = payload.description else {
                        return Err(TlsTranscriptError::validation(
                            "sent alert that is not close notify",
                        ));
                    };
                }
                typ => {
                    return Err(TlsTranscriptError::validation(format!(
                        "sent unexpected record content type: {typ:?}"
                    )))
                }
            }
        }

        // Verify last record received was either application data or close notify.
        if let Some(record) = recv_iter.next_back() {
            match record.typ {
                ContentType::ApplicationData => {}
                ContentType::Alert => {
                    // Ensure the alert is a close notify.
                    let payload =
                        record
                            .plaintext
                            .as_ref()
                            .ok_or(TlsTranscriptError::validation(
                                "alert content was hidden from the follower",
                            ))?;

                    let mut reader = Reader::init(payload);
                    let payload = AlertMessagePayload::read(&mut reader).ok_or(
                        TlsTranscriptError::validation("alert message was malformed"),
                    )?;

                    let AlertDescription::CloseNotify = payload.description else {
                        return Err(TlsTranscriptError::validation(
                            "received alert that is not close notify",
                        ));
                    };
                }
                typ => {
                    return Err(TlsTranscriptError::validation(format!(
                        "received unexpected record content type: {typ:?}"
                    )))
                }
            }
        }

        // Ensure all other records were application data.
        for record in sent_iter {
            if record.typ != ContentType::ApplicationData {
                return Err(TlsTranscriptError::validation(format!(
                    "sent unexpected record content type: {:?}",
                    record.typ
                )));
            }
        }

        for record in recv_iter {
            if record.typ != ContentType::ApplicationData {
                return Err(TlsTranscriptError::validation(format!(
                    "received unexpected record content type: {:?}",
                    record.typ
                )));
            }
        }

        Ok(Self {
            time,
            version,
            server_cert_chain,
            server_signature,
            handshake_data,
            sent,
            recv,
        })
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
        self.server_cert_chain.as_deref()
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

#[derive(Debug, thiserror::Error)]
#[error("TLS transcript error: {0}")]
pub struct TlsTranscriptError(#[from] ErrorRepr);

impl TlsTranscriptError {
    fn validation(msg: impl Into<String>) -> Self {
        Self(ErrorRepr::Validation(msg.into()))
    }
}

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("validation error: {0}")]
    Validation(String),
    #[error("incomplete transcript ({direction}): seq {seq}")]
    Incomplete { direction: Direction, seq: u64 },
}
