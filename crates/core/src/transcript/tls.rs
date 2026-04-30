//! TLS transcript.

use const_oid::db::rfc5912;
use rustls_pki_types as pki_types;
use spki::der::{Decode, oid::ObjectIdentifier};

use crate::{
    connection::{
        CertBinding, CertBindingV1_2, HandshakeData, KeyType, ServerEphemKey, ServerSignature,
        SignatureAlgorithm, TlsVersion, VerifyData,
    },
    transcript::{Direction, Transcript},
    webpki::CertificateDer,
};
use sha2::{Digest, Sha256};
use tls_core::msgs::{
    alert::AlertMessagePayload,
    codec::{Codec, Reader},
    enums::{
        AlertDescription, ContentType as TlsContentType, HandshakeType, NamedGroup,
        ProtocolVersion, SignatureScheme,
    },
    handshake::{HandshakeMessagePayload, HandshakePayload, KeyExchangeAlgorithm},
    message::OpaqueMessage,
};

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

/// A transcript of TLS records sent and received by the prover.
#[derive(Debug, Clone)]
pub struct TlsTranscript {
    time: u64,
    version: TlsVersion,
    server_cert_chain: Option<Vec<CertificateDer>>,
    server_signature: Option<ServerSignature>,
    certificate_binding: CertBinding,
    sent: Vec<Record>,
    recv: Vec<Record>,
    cf_vd: Record,
    sf_vd: Record,
}

impl TlsTranscript {
    /// Creates a new TLS transcript.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        time: u64,
        version: TlsVersion,
        server_cert_chain: Option<Vec<CertificateDer>>,
        server_signature: Option<ServerSignature>,
        certificate_binding: CertBinding,
        plain_verify_data: Option<VerifyData>,
        sent: Vec<Record>,
        recv: Vec<Record>,
        cf_vd: Record,
        sf_vd: Record,
    ) -> Result<Self, TlsTranscriptError> {
        // Check for client finished consistency if possible.
        if let Some(verify_data) = &plain_verify_data {
            let payload = cf_vd
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
        }

        // Check for server_finished finished consistency if possible.
        if let Some(verify_data) = &plain_verify_data {
            let payload = sf_vd
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
        }

        let mut sent_iter = sent.iter();
        let mut recv_iter = recv.iter();

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
                    )));
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
                    )));
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
            certificate_binding,
            sent,
            recv,
            cf_vd,
            sf_vd,
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
    pub fn server_cert_chain(&self) -> Option<&[CertificateDer]> {
        self.server_cert_chain.as_deref()
    }

    /// Returns the server signature.
    pub fn server_signature(&self) -> Option<&ServerSignature> {
        self.server_signature.as_ref()
    }

    /// Returns the server ephemeral key used in the TLS handshake.
    pub fn server_ephemeral_key(&self) -> &ServerEphemKey {
        match &self.certificate_binding {
            CertBinding::V1_2(CertBindingV1_2 {
                server_ephemeral_key,
                ..
            }) => server_ephemeral_key,
        }
    }

    /// Returns the certificate binding data.
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

    /// Returns the client finished verify data record
    pub fn cf_vd(&self) -> &Record {
        &self.cf_vd
    }

    /// Returns the client finished verify data record
    pub fn sf_vd(&self) -> &Record {
        &self.sf_vd
    }

    /// Computes the TLS 1.2 Extended Master Secret `session_hash`
    /// (RFC 7627 §3) directly from the raw wire bytes.
    ///
    /// `session_hash` is the hash of all plaintext handshake messages
    /// from `ClientHello` through `ClientKeyExchange`, in the order
    /// they appear on the wire (and explicitly excluding any
    /// `CertificateVerify`).
    ///
    /// SHA-256 is hard-coded as the PRF hash, matching the two
    /// whitelisted suites in proxy mode
    /// (`TLS_ECDHE_*_WITH_AES_128_GCM_SHA256`). If the suite list is
    /// widened to include suites with a different PRF hash, this
    /// function must be extended to take the cipher suite as input.
    pub fn compute_session_hash(sent: &[u8], recv: &[u8]) -> Result<[u8; 32], TlsTranscriptError> {
        let sent_records = parse_raw_records(sent)?;
        let recv_records = parse_raw_records(recv)?;

        let sent_hs_bytes = collect_handshake_bytes_pre_ccs(&sent_records);
        let recv_hs_bytes = collect_handshake_bytes_pre_ccs(&recv_records);

        let sent_msgs = scan_handshake_messages(&sent_hs_bytes)?;
        let recv_msgs = scan_handshake_messages(&recv_hs_bytes)?;

        // The first sent handshake message must be ClientHello.
        let client_hello = sent_msgs.first().ok_or_else(|| {
            TlsTranscriptError::parse("missing ClientHello in sent handshake stream")
        })?;
        if client_hello.typ != HandshakeType::ClientHello {
            return Err(TlsTranscriptError::parse(
                "first sent handshake message is not ClientHello",
            ));
        }

        // ClientKeyExchange must be present and bounds the session_hash window.
        let ckx = sent_msgs
            .iter()
            .find(|m| m.typ == HandshakeType::ClientKeyExchange)
            .ok_or_else(|| TlsTranscriptError::parse("missing ClientKeyExchange"))?;

        // Server side must contain ServerHello and ServerHelloDone.
        if !recv_msgs
            .iter()
            .any(|m| m.typ == HandshakeType::ServerHello)
        {
            return Err(TlsTranscriptError::parse("missing ServerHello"));
        }
        if !recv_msgs
            .iter()
            .any(|m| m.typ == HandshakeType::ServerHelloDone)
        {
            return Err(TlsTranscriptError::parse("missing ServerHelloDone"));
        }

        // Wire order: ClientHello → server flight (ServerHello..ServerHelloDone)
        // → client flight up to and including ClientKeyExchange. Any
        // CertificateVerify that may follow on the sent side is excluded
        // by stopping at ckx.end.
        let mut hasher = Sha256::new();
        hasher.update(&sent_hs_bytes[..client_hello.end]);
        hasher.update(&recv_hs_bytes);
        hasher.update(&sent_hs_bytes[client_hello.end..ckx.end]);

        Ok(hasher.finalize().into())
    }

    /// Computes the handshake hash used as the seed for the TLS 1.2
    /// Client Finished verify-data computation (`cf_hash`).
    ///
    /// This is the SHA-256 hash of every plaintext handshake message
    /// that precedes the Client Finished message, in wire order:
    pub fn compute_cf_hash(sent: &[u8], recv: &[u8]) -> Result<[u8; 32], TlsTranscriptError> {
        let sent_records = parse_raw_records(sent)?;
        let recv_records = parse_raw_records(recv)?;

        let sent_hs_bytes = collect_handshake_bytes_pre_ccs(&sent_records);
        let recv_hs_bytes = collect_handshake_bytes_pre_ccs(&recv_records);

        let sent_msgs = scan_handshake_messages(&sent_hs_bytes)?;
        let recv_msgs = scan_handshake_messages(&recv_hs_bytes)?;

        let client_hello = sent_msgs.first().ok_or_else(|| {
            TlsTranscriptError::parse("missing ClientHello in sent handshake stream")
        })?;
        if client_hello.typ != HandshakeType::ClientHello {
            return Err(TlsTranscriptError::parse(
                "first sent handshake message is not ClientHello",
            ));
        }

        if !recv_msgs
            .iter()
            .any(|m| m.typ == HandshakeType::ServerHello)
        {
            return Err(TlsTranscriptError::parse("missing ServerHello"));
        }
        let shd = recv_msgs
            .iter()
            .find(|m| m.typ == HandshakeType::ServerHelloDone)
            .ok_or_else(|| TlsTranscriptError::parse("missing ServerHelloDone"))?;

        // Server's first flight ends at ServerHelloDone. Anything in the
        // pre-CCS recv stream after that (notably an RFC 5077
        // NewSessionTicket) arrives on the wire after the Client Finished
        // and must not enter cf_hash.
        let recv_first_flight = &recv_hs_bytes[..shd.end];

        // Wire order: ClientHello → server first flight → remaining client
        // flight (ClientKeyExchange and, when client auth is active,
        // CertificateVerify). All pre-CCS bytes on the sent side are
        // included.
        let mut hasher = Sha256::new();
        hasher.update(&sent_hs_bytes[..client_hello.end]);
        hasher.update(recv_first_flight);
        hasher.update(&sent_hs_bytes[client_hello.end..]);

        Ok(hasher.finalize().into())
    }

    /// Computes the handshake hash used as the seed for the TLS 1.2
    /// Server Finished verify-data computation (`sf_hash`).
    ///
    /// This equals `cf_hash` with the Client Finished handshake
    /// message appended:
    pub fn compute_sf_hash(
        sent: &[u8],
        recv: &[u8],
        cf_vd: &[u8; 12],
    ) -> Result<[u8; 32], TlsTranscriptError> {
        let sent_records = parse_raw_records(sent)?;
        let recv_records = parse_raw_records(recv)?;

        let sent_hs_bytes = collect_handshake_bytes_pre_ccs(&sent_records);
        let recv_hs_bytes = collect_handshake_bytes_pre_ccs(&recv_records);

        let sent_msgs = scan_handshake_messages(&sent_hs_bytes)?;
        let recv_msgs = scan_handshake_messages(&recv_hs_bytes)?;

        let client_hello = sent_msgs.first().ok_or_else(|| {
            TlsTranscriptError::parse("missing ClientHello in sent handshake stream")
        })?;
        if client_hello.typ != HandshakeType::ClientHello {
            return Err(TlsTranscriptError::parse(
                "first sent handshake message is not ClientHello",
            ));
        }

        if !recv_msgs
            .iter()
            .any(|m| m.typ == HandshakeType::ServerHello)
        {
            return Err(TlsTranscriptError::parse("missing ServerHello"));
        }
        let shd = recv_msgs
            .iter()
            .find(|m| m.typ == HandshakeType::ServerHelloDone)
            .ok_or_else(|| TlsTranscriptError::parse("missing ServerHelloDone"))?;

        // Split pre-CCS recv bytes at ServerHelloDone. Anything after
        // (notably an RFC 5077 NewSessionTicket) arrives on the wire
        // after the Client Finished and must be hashed in that position.
        let (recv_first_flight, recv_post_cf) = recv_hs_bytes.split_at(shd.end);

        let mut hasher = Sha256::new();
        hasher.update(&sent_hs_bytes[..client_hello.end]);
        hasher.update(recv_first_flight);
        hasher.update(&sent_hs_bytes[client_hello.end..]);
        // Append the reconstructed Client Finished handshake message.
        hasher.update([0x14, 0x00, 0x00, 0x0c]);
        hasher.update(cf_vd);
        hasher.update(recv_post_cf);

        Ok(hasher.finalize().into())
    }

    /// Parses a complete TLS transcript from raw wire bytes.
    ///
    /// # Arguments
    ///
    /// * `time` - UNIX timestamp of the connection.
    /// * `sent` - Raw TLS bytes sent (client → server).
    /// * `recv` - Raw TLS bytes received (server → client).
    /// * `sent_app` - Plaintext application data sent.
    /// * `recv_app` - Plaintext application data received.
    pub fn parse(
        time: u64,
        sent: &[u8],
        recv: &[u8],
        sent_app: &[u8],
        recv_app: &[u8],
    ) -> Result<Self, TlsTranscriptError> {
        let sent_records = parse_raw_records(sent)?;
        let recv_records = parse_raw_records(recv)?;

        let sent_hs = assemble_handshake_messages(&sent_records)?;
        let recv_hs = assemble_handshake_messages(&recv_records)?;

        let (version, handshake) = extract_handshake(&sent_hs, &recv_hs)?;

        let sent_vd = parse_verify_data_record(&sent_records)?;
        let recv_vd = parse_verify_data_record(&recv_records)?;

        let sent = parse_app_records(&sent_records, sent_app)?;
        let recv = parse_app_records(&recv_records, recv_app)?;

        Self::new(
            time,
            version,
            Some(handshake.certs),
            Some(handshake.sig),
            handshake.binding,
            None,
            sent,
            recv,
            sent_vd,
            recv_vd,
        )
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

/// Error type.
#[derive(Debug, thiserror::Error)]
#[error("TLS transcript error: {0}")]
pub struct TlsTranscriptError(#[from] ErrorRepr);

impl TlsTranscriptError {
    fn validation(msg: impl Into<String>) -> Self {
        Self(ErrorRepr::Validation(msg.into()))
    }

    fn parse(msg: impl Into<String>) -> Self {
        Self(ErrorRepr::Parse(msg.into()))
    }
}

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("validation error: {0}")]
    Validation(String),
    #[error("parse error: {0}")]
    Parse(String),
    #[error("incomplete transcript ({direction}): seq {seq}")]
    Incomplete { direction: Direction, seq: u64 },
}

// ---------------------------------------------------------------------------
// Private parsing helpers
// ---------------------------------------------------------------------------

const NONCE_LEN: usize = 8;
const TAG_LEN: usize = 16;

/// Parse raw TLS record frames from a byte slice.
fn parse_raw_records(bytes: &[u8]) -> Result<Vec<OpaqueMessage>, TlsTranscriptError> {
    let mut reader = Reader::init(bytes);
    let mut records = Vec::new();
    while reader.any_left() {
        let msg = OpaqueMessage::read(&mut reader)
            .map_err(|e| TlsTranscriptError::parse(format!("failed to read TLS record: {e:?}")))?;
        records.push(msg);
    }
    Ok(records)
}

/// Collect handshake record payloads (up to CCS) and parse them into
/// individual handshake messages.
fn assemble_handshake_messages(
    records: &[OpaqueMessage],
) -> Result<Vec<HandshakeMessagePayload>, TlsTranscriptError> {
    let handshake_bytes = collect_handshake_bytes_pre_ccs(records);

    let mut reader = Reader::init(&handshake_bytes);
    let mut messages = Vec::new();
    while reader.any_left() {
        let msg = HandshakeMessagePayload::read_version(&mut reader, ProtocolVersion::TLSv1_2)
            .ok_or_else(|| TlsTranscriptError::parse("failed to parse handshake message"))?;
        messages.push(msg);
    }
    Ok(messages)
}

/// Concatenate the payload bytes of all handshake records appearing
/// before the first ChangeCipherSpec. These are the plaintext
/// handshake bytes as they appeared on the wire.
fn collect_handshake_bytes_pre_ccs(records: &[OpaqueMessage]) -> Vec<u8> {
    let mut handshake_bytes = Vec::new();
    for record in records {
        if record.typ == TlsContentType::ChangeCipherSpec {
            break;
        }
        if record.typ == TlsContentType::Handshake {
            handshake_bytes.extend_from_slice(&record.payload.0);
        }
    }
    handshake_bytes
}

/// Position information for a single handshake message inside a
/// concatenated handshake byte stream.
struct HandshakeMsgInfo {
    typ: HandshakeType,
    /// Exclusive end offset of the message (header + body) in the
    /// scanned byte stream.
    end: usize,
}

/// Walk a concatenated handshake byte stream and return the type and
/// end offset of each message. Each message is a 1-byte type, a
/// 3-byte big-endian length, and a body of that length.
fn scan_handshake_messages(bytes: &[u8]) -> Result<Vec<HandshakeMsgInfo>, TlsTranscriptError> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < bytes.len() {
        if bytes.len() - pos < 4 {
            return Err(TlsTranscriptError::parse("truncated handshake header"));
        }
        let typ = HandshakeType::from(bytes[pos]);
        let len = u32::from_be_bytes([0, bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]) as usize;
        let msg_end = pos + 4 + len;
        if msg_end > bytes.len() {
            return Err(TlsTranscriptError::parse(
                "handshake message length overflows buffer",
            ));
        }
        out.push(HandshakeMsgInfo { typ, end: msg_end });
        pos = msg_end;
    }
    Ok(out)
}

/// Find the index of the first ChangeCipherSpec record.
fn find_ccs(records: &[OpaqueMessage]) -> Option<usize> {
    records
        .iter()
        .position(|r| r.typ == TlsContentType::ChangeCipherSpec)
}

/// Split an encrypted TLS record payload into nonce / ciphertext / tag.
fn split_into_record(
    seq: u64,
    payload: &[u8],
    typ: TlsContentType,
) -> Result<Record, TlsTranscriptError> {
    let typ = ContentType::from(typ);

    if payload.len() < NONCE_LEN + TAG_LEN {
        return Err(TlsTranscriptError::parse("encrypted record too short"));
    }

    Ok(Record {
        seq,
        typ,
        plaintext: None,
        explicit_nonce: payload[..NONCE_LEN].to_vec(),
        ciphertext: payload[NONCE_LEN..payload.len() - TAG_LEN].to_vec(),
        tag: Some(payload[payload.len() - TAG_LEN..].to_vec()),
    })
}

/// Extract the full handshake data from parsed handshake messages.
fn extract_handshake(
    sent_hs: &[HandshakeMessagePayload],
    recv_hs: &[HandshakeMessagePayload],
) -> Result<(TlsVersion, HandshakeData), TlsTranscriptError> {
    let (version, server_random) = extract_server_hello_data(recv_hs)?;
    let client_random = extract_client_random(sent_hs)?;
    let certs = extract_certs(recv_hs)?;
    let (server_ephemeral_key, sig) = extract_server_key_exchange(recv_hs, &certs)?;

    let binding = CertBinding::V1_2(CertBindingV1_2 {
        client_random,
        server_random,
        server_ephemeral_key,
    });

    let handshake = HandshakeData {
        certs,
        sig,
        binding,
    };

    Ok((version, handshake))
}

/// Extract the TLS version and server random from the ServerHello message.
fn extract_server_hello_data(
    recv_hs: &[HandshakeMessagePayload],
) -> Result<(TlsVersion, [u8; 32]), TlsTranscriptError> {
    let server_hello = recv_hs
        .iter()
        .find_map(|msg| match &msg.payload {
            HandshakePayload::ServerHello(sh) => Some(sh),
            _ => None,
        })
        .ok_or_else(|| TlsTranscriptError::parse("missing ServerHello"))?;

    let version = TlsVersion::try_from(server_hello.legacy_version)
        .map_err(|e| TlsTranscriptError::parse(format!("unsupported TLS version: {e}")))?;

    Ok((version, server_hello.random.0))
}

fn extract_client_random(
    sent_hs: &[HandshakeMessagePayload],
) -> Result<[u8; 32], TlsTranscriptError> {
    let client_hello = sent_hs
        .iter()
        .find_map(|msg| match &msg.payload {
            HandshakePayload::ClientHello(ch) => Some(ch),
            _ => None,
        })
        .ok_or_else(|| TlsTranscriptError::parse("missing ClientHello"))?;

    Ok(client_hello.random.0)
}

fn extract_certs(
    recv_hs: &[HandshakeMessagePayload],
) -> Result<Vec<CertificateDer>, TlsTranscriptError> {
    let cert_payload = recv_hs
        .iter()
        .find_map(|msg| match &msg.payload {
            HandshakePayload::Certificate(certs) => Some(certs),
            _ => None,
        })
        .ok_or_else(|| TlsTranscriptError::parse("missing Certificate"))?;

    Ok(cert_payload
        .iter()
        .map(|cert| CertificateDer(cert.0.clone()))
        .collect())
}

fn extract_server_key_exchange(
    recv_hs: &[HandshakeMessagePayload],
    certs: &[CertificateDer],
) -> Result<(ServerEphemKey, ServerSignature), TlsTranscriptError> {
    let ske = recv_hs
        .iter()
        .find_map(|msg| match &msg.payload {
            HandshakePayload::ServerKeyExchange(ske) => Some(ske),
            _ => None,
        })
        .ok_or_else(|| TlsTranscriptError::parse("missing ServerKeyExchange"))?;

    let ecdhe = ske
        .unwrap_given_kxa(&KeyExchangeAlgorithm::ECDHE)
        .ok_or_else(|| TlsTranscriptError::parse("failed to parse ECDHE ServerKeyExchange"))?;

    if ecdhe.params.curve_params.named_group != NamedGroup::secp256r1 {
        return Err(TlsTranscriptError::parse(
            "unsupported key exchange group (only secp256r1 is supported)",
        ));
    }

    let key = ServerEphemKey {
        typ: KeyType::SECP256R1,
        key: ecdhe.params.public.0.clone(),
    };

    let alg = map_signature_scheme(ecdhe.dss.scheme, certs)?;
    let sig = ServerSignature {
        alg,
        sig: ecdhe.dss.sig.0.clone(),
    };

    Ok((key, sig))
}

/// Map a TLS `SignatureScheme` to our `SignatureAlgorithm`.
///
/// For ECDSA in TLS 1.2 the scheme only specifies the hash, not the curve.
/// The curve is determined from the end-entity certificate's public key.
fn map_signature_scheme(
    scheme: SignatureScheme,
    certs: &[CertificateDer],
) -> Result<SignatureAlgorithm, TlsTranscriptError> {
    match scheme {
        SignatureScheme::RSA_PKCS1_SHA256 => Ok(SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA256),
        SignatureScheme::RSA_PKCS1_SHA384 => Ok(SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA384),
        SignatureScheme::RSA_PKCS1_SHA512 => Ok(SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA512),
        SignatureScheme::RSA_PSS_SHA256 => {
            Ok(SignatureAlgorithm::RSA_PSS_2048_8192_SHA256_LEGACY_KEY)
        }
        SignatureScheme::RSA_PSS_SHA384 => {
            Ok(SignatureAlgorithm::RSA_PSS_2048_8192_SHA384_LEGACY_KEY)
        }
        SignatureScheme::RSA_PSS_SHA512 => {
            Ok(SignatureAlgorithm::RSA_PSS_2048_8192_SHA512_LEGACY_KEY)
        }
        SignatureScheme::ED25519 => Ok(SignatureAlgorithm::ED25519),
        // In TLS 1.2, ECDSA schemes specify only the hash — the curve
        // comes from the server certificate's public key.
        SignatureScheme::ECDSA_NISTP256_SHA256 => {
            let curve_oid = extract_ec_curve_oid(certs)?;
            match curve_oid {
                oid if oid == rfc5912::SECP_256_R_1 => {
                    Ok(SignatureAlgorithm::ECDSA_NISTP256_SHA256)
                }
                oid if oid == rfc5912::SECP_384_R_1 => {
                    Ok(SignatureAlgorithm::ECDSA_NISTP384_SHA256)
                }
                _ => Err(TlsTranscriptError::parse(format!(
                    "unsupported EC curve: {curve_oid}"
                ))),
            }
        }
        SignatureScheme::ECDSA_NISTP384_SHA384 => {
            let curve_oid = extract_ec_curve_oid(certs)?;
            match curve_oid {
                oid if oid == rfc5912::SECP_256_R_1 => {
                    Ok(SignatureAlgorithm::ECDSA_NISTP256_SHA384)
                }
                oid if oid == rfc5912::SECP_384_R_1 => {
                    Ok(SignatureAlgorithm::ECDSA_NISTP384_SHA384)
                }
                _ => Err(TlsTranscriptError::parse(format!(
                    "unsupported EC curve: {curve_oid}"
                ))),
            }
        }
        _ => Err(TlsTranscriptError::parse(format!(
            "unsupported signature scheme: {scheme:?}"
        ))),
    }
}

/// Extract the EC curve OID from the end-entity certificate's SPKI.
fn extract_ec_curve_oid(certs: &[CertificateDer]) -> Result<ObjectIdentifier, TlsTranscriptError> {
    let ee_cert = certs
        .first()
        .ok_or_else(|| TlsTranscriptError::parse("missing end-entity certificate"))?;

    let cert = pki_types::CertificateDer::from(ee_cert.0.as_slice());
    let ee = webpki::EndEntityCert::try_from(&cert)
        .map_err(|e| TlsTranscriptError::parse(format!("invalid end-entity certificate: {e}")))?;
    let spki_der = ee.subject_public_key_info();
    let spki = spki::SubjectPublicKeyInfoRef::from_der(spki_der.as_ref())
        .map_err(|e| TlsTranscriptError::parse(format!("invalid SPKI: {e}")))?;
    spki.algorithm
        .parameters
        .ok_or_else(|| TlsTranscriptError::parse("missing EC curve parameters in SPKI"))?
        .decode_as::<ObjectIdentifier>()
        .map_err(|e| TlsTranscriptError::parse(format!("failed to decode EC curve OID: {e}")))
}

/// Parses the verify data record without decrypting the plaintext.
fn parse_verify_data_record(records: &[OpaqueMessage]) -> Result<Record, TlsTranscriptError> {
    let ccs = find_ccs(records)
        .ok_or_else(|| TlsTranscriptError::parse("missing ChangeCipherSpec record"))?;

    let raw_finished = records
        .get(ccs + 1)
        .ok_or_else(|| TlsTranscriptError::parse("missing Finished record after CCS"))?;

    split_into_record(0, &raw_finished.payload.0, raw_finished.typ)
}

/// Parse application data records after the CCS + Finished boundary.
fn parse_app_records(
    records: &[OpaqueMessage],
    app_data: &[u8],
) -> Result<Vec<Record>, TlsTranscriptError> {
    let mut consumed = 0;
    let mut parsed = Vec::new();

    let Some(start) = find_ccs(records) else {
        return Ok(parsed);
    };

    // Skip CCS and the Finished record.
    for (seq, record) in (1u64..).zip(records.iter().skip(start + 2)) {
        let mut rec = split_into_record(seq, &record.payload.0, record.typ)?;

        if rec.typ == ContentType::ApplicationData {
            if !app_data.is_empty() {
                let cipher_len = rec.ciphertext.len();
                if app_data[consumed..].len() >= cipher_len {
                    rec.plaintext = Some(app_data[consumed..consumed + cipher_len].to_vec());
                    consumed += cipher_len;
                } else {
                    return Err(TlsTranscriptError::parse(
                        "insufficient plaintext application data",
                    ));
                }
            }
            parsed.push(rec);
        }
    }

    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::KeyType;
    use tls_server_fixture::SERVER_CERT_DER;

    // Pre-generated TLS 1.2 transcript fixtures. Captured once from a real
    // handshake against `tls_server_fixture::bind_test_server` followed by
    // four `msgN` records (each padded to 1024 bytes) echoed as "hello".
    // The server certificate is `tls_server_fixture::SERVER_CERT_DER`, so
    // regenerate these files if that cert ever changes.
    const SENT: &[u8] = include_bytes!("fixtures/tls_sent.bin");
    const RECV: &[u8] = include_bytes!("fixtures/tls_recv.bin");
    const APP_SENT: &[u8] = include_bytes!("fixtures/tls_app_sent.bin");
    const APP_RECV: &[u8] = include_bytes!("fixtures/tls_app_recv.bin");
    const MSG_COUNT: usize = 4;
    const REQUEST_PLAIN: &str = "msg";
    const RESPONSE_PLAIN: &str = "hello";

    #[test]
    fn test_parse_handshake() {
        let transcript = TlsTranscript::parse(0, SENT, RECV, &[], &[]).unwrap();

        assert_eq!(*transcript.version(), TlsVersion::V1_2);

        // Certificate chain should contain the server cert.
        assert_eq!(
            transcript.server_cert_chain().unwrap()[0].0,
            SERVER_CERT_DER
        );

        // Signature algorithm should be an RSA variant.
        let alg = &transcript.server_signature().unwrap().alg;
        assert!(
            matches!(
                alg,
                SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA256
                    | SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA384
                    | SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA512
                    | SignatureAlgorithm::RSA_PSS_2048_8192_SHA256_LEGACY_KEY
                    | SignatureAlgorithm::RSA_PSS_2048_8192_SHA384_LEGACY_KEY
                    | SignatureAlgorithm::RSA_PSS_2048_8192_SHA512_LEGACY_KEY
            ),
            "expected RSA signature algorithm, got {:?}",
            alg
        );

        // CertBinding should be V1_2 with valid values.
        let CertBinding::V1_2(binding) = transcript.certificate_binding();

        assert_ne!(binding.client_random, [0u8; 32]);
        assert_ne!(binding.server_random, [0u8; 32]);
        assert_eq!(binding.server_ephemeral_key.typ, KeyType::SECP256R1);
        // Uncompressed EC point: 65 bytes, starts with 0x04.
        assert_eq!(binding.server_ephemeral_key.key.len(), 65);
        assert_eq!(binding.server_ephemeral_key.key[0], 0x04);
    }

    #[test]
    fn test_parse_app_records() {
        let sent_raw = parse_raw_records(SENT).unwrap();
        let recv_raw = parse_raw_records(RECV).unwrap();
        let sent_records = parse_app_records(&sent_raw, APP_SENT).unwrap();
        let recv_records = parse_app_records(&recv_raw, APP_RECV).unwrap();

        // Sent records: 4 messages, seq 1..=4.
        assert_eq!(sent_records.len(), MSG_COUNT);
        for (i, record) in sent_records.iter().enumerate() {
            let expected_seq = (i + 1) as u64;
            assert_eq!(record.seq, expected_seq);
            assert_eq!(record.typ, ContentType::ApplicationData);
            assert_eq!(record.explicit_nonce.len(), 8);
            assert!(!record.ciphertext.is_empty());
            assert_eq!(record.tag.as_ref().unwrap().len(), 16);

            let plaintext = record.plaintext.as_ref().expect("plaintext should be set");
            let plain_str = std::str::from_utf8(plaintext).expect("plaintext is valid utf-8");
            assert!(plain_str.contains(REQUEST_PLAIN));
        }

        // Recv records: 4 "hello" responses, seq 1..=4.
        assert_eq!(recv_records.len(), MSG_COUNT);
        for (i, record) in recv_records.iter().enumerate() {
            let expected_seq = (i + 1) as u64;
            assert_eq!(record.seq, expected_seq);
            assert_eq!(record.typ, ContentType::ApplicationData);
            assert_eq!(record.explicit_nonce.len(), 8);
            assert!(!record.ciphertext.is_empty());
            assert_eq!(record.tag.as_ref().unwrap().len(), 16);

            let plaintext = record.plaintext.as_ref().expect("plaintext should be set");
            assert_eq!(plaintext, RESPONSE_PLAIN.as_bytes());
        }
    }

    #[test]
    fn test_parse_into_transcript() {
        let transcript = TlsTranscript::parse(0, SENT, RECV, APP_SENT, APP_RECV).unwrap();

        assert_eq!(*transcript.version(), TlsVersion::V1_2);
        assert!(transcript.server_cert_chain().is_some());
        assert!(transcript.server_signature().is_some());

        // First sent/recv records are the Finished messages (seq 0).
        assert_eq!(transcript.sent()[0].seq, 0);
        assert_eq!(transcript.recv()[0].seq, 0);

        // 1 finished record, 4 app data records.
        assert_eq!(transcript.sent().len(), 5);
        assert_eq!(transcript.recv().len(), 5);
    }
}
