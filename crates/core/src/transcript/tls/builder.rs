//! Builder type for [`TlsTranscript`].

use const_oid::db::rfc5912;
use rustls_pki_types as pki_types;
use sha2::{Digest, Sha256};
use spki::der::{Decode, oid::ObjectIdentifier};
use tls_core::msgs::{
    codec::Reader,
    enums::{
        ContentType as TlsContentType, HandshakeType, NamedGroup, ProtocolVersion, SignatureScheme,
    },
    handshake::{HandshakeMessagePayload, HandshakePayload, KeyExchangeAlgorithm},
    message::OpaqueMessage,
};

use crate::{
    connection::{
        CertBinding, CertBindingV1_2, HandshakeData, KeyType, ServerEphemKey, ServerSignature,
        SignatureAlgorithm, TlsVersion,
    },
    webpki::CertificateDer,
};

use super::{ContentType, Record, TlsTranscript, TlsTranscriptError};

/// Builder for [`TlsTranscript`].
#[derive(Debug, Default)]
pub struct TlsTranscriptBuilder<'a> {
    time: Option<u64>,
    version: Option<TlsVersion>,
    tls_sent: Option<&'a [u8]>,
    tls_recv: Option<&'a [u8]>,
    app_sent: Option<&'a [u8]>,
    app_recv: Option<&'a [u8]>,
    records_sent: Option<Vec<Record>>,
    records_recv: Option<Vec<Record>>,
    server_signature: Option<ServerSignature>,
    server_cert_chain: Option<Vec<CertificateDer>>,
    certificate_binding: Option<CertBinding>,
}

impl<'a> TlsTranscriptBuilder<'a> {
    /// Sets the time.
    pub fn time(mut self, time: u64) -> Self {
        self.time = Some(time);
        self
    }

    /// Sets the TLS version.
    pub fn version(mut self, version: TlsVersion) -> Self {
        self.version = Some(version);
        self
    }

    /// Sets the tls data sent.
    pub fn tls_sent(mut self, data: &'a [u8]) -> Self {
        self.tls_sent = Some(data);
        self
    }

    /// Sets the tls data received.
    pub fn tls_recv(mut self, recv: &'a [u8]) -> Self {
        self.tls_recv = Some(recv);
        self
    }

    /// Sets the plaintext application data sent.
    pub fn app_sent(mut self, sent: &'a [u8]) -> Self {
        self.app_sent = Some(sent);
        self
    }

    /// Sets the plaintext application data received.
    pub fn app_recv(mut self, recv: &'a [u8]) -> Self {
        self.app_recv = Some(recv);
        self
    }

    /// Sets the sent records. First record must be client_finished record.
    pub fn records_sent(mut self, sent: Vec<Record>) -> Self {
        self.records_sent = Some(sent);
        self
    }

    /// Sets the received records. First record must be the server finished
    /// record.
    pub fn records_recv(mut self, recv: Vec<Record>) -> Self {
        self.records_recv = Some(recv);
        self
    }

    /// Sets the server signature.
    pub fn server_signature(mut self, sig: ServerSignature) -> Self {
        self.server_signature = Some(sig);
        self
    }

    /// Sets the server certificate chain.
    pub fn server_cert_chain(mut self, chain: Vec<CertificateDer>) -> Self {
        self.server_cert_chain = Some(chain);
        self
    }

    /// Sets the certificate binding.
    pub fn certificate_binding(mut self, binding: CertBinding) -> Self {
        self.certificate_binding = Some(binding);
        self
    }

    /// Builds a [`TlsTranscript`].
    ///
    /// Prefers available fields, but if missing tries to parse.
    pub fn build(mut self) -> Result<TlsTranscript, TlsTranscriptError> {
        let time = self
            .time
            .ok_or_else(|| TlsTranscriptError::missing("time"))?;

        let sent_raw = if let Some(tls_sent) = self.tls_sent {
            Some(parse_raw_records(tls_sent)?)
        } else {
            None
        };

        let recv_raw = if let Some(tls_recv) = self.tls_recv {
            Some(parse_raw_records(tls_recv)?)
        } else {
            None
        };

        let (cf_hash, session_hash, sf_hash) = if let Some(sent_raw) = &sent_raw
            && let Some(recv_raw) = &recv_raw
        {
            let (cf_hash, session_hash, sf_hash) =
                self.parse_handshake_components(sent_raw, recv_raw)?;
            (Some(cf_hash), Some(session_hash), Some(sf_hash))
        } else {
            (None, None, None)
        };

        let sent = if let Some(records_sent) = self.records_sent {
            let client_finished = records_sent
                .first()
                .expect("client finished record should be available");
            validate_finished_record(client_finished)?;
            records_sent
        } else if let Some(sent_raw) = sent_raw {
            parse_records(&sent_raw, self.app_sent)?
        } else {
            return Err(TlsTranscriptError::missing("sent records"));
        };
        validate_seq(&sent)?;

        let recv = if let Some(records_recv) = self.records_recv {
            let server_finished = records_recv
                .first()
                .expect("server finished record should be available");
            validate_finished_record(server_finished)?;
            records_recv
        } else if let Some(recv_raw) = recv_raw {
            parse_records(&recv_raw, self.app_recv)?
        } else {
            return Err(TlsTranscriptError::missing("recv records"));
        };
        validate_seq(&recv)?;

        let version = self
            .version
            .ok_or_else(|| TlsTranscriptError::missing("version"))?;
        let certificate_binding = self
            .certificate_binding
            .ok_or_else(|| TlsTranscriptError::missing("certificate binding"))?;

        let transcript = TlsTranscript {
            time,
            version,
            server_signature: self.server_signature,
            server_cert_chain: self.server_cert_chain,
            certificate_binding,
            cf_hash,
            session_hash,
            sf_hash,
            sent,
            recv,
        };

        Ok(transcript)
    }

    /// Parse the pre-CCS handshake from both directions.
    fn parse_handshake_components(
        &mut self,
        sent_records: &[OpaqueMessage],
        recv_records: &[OpaqueMessage],
    ) -> Result<([u8; 32], [u8; 32], SfHashInput), TlsTranscriptError> {
        let (sent_hs_bytes, sent_hs) = parse_handshake_stream(sent_records)?;
        let (recv_hs_bytes, recv_hs) = parse_handshake_stream(recv_records)?;

        let (version, handshake) = extract_handshake(&sent_hs, &recv_hs)?;

        let sent_msgs = scan_handshake_messages(&sent_hs_bytes)?;
        let recv_msgs = scan_handshake_messages(&recv_hs_bytes)?;
        let (cf_hash, session_hash, sf_hash_input) =
            compute_handshake_hashes(sent_hs_bytes, recv_hs_bytes, &sent_msgs, &recv_msgs)?;

        if self.version.is_none() {
            self.version = Some(version);
        }
        if self.server_signature.is_none() {
            self.server_signature = Some(handshake.sig);
        }
        if self.server_cert_chain.is_none() {
            self.server_cert_chain = Some(handshake.certs);
        }
        if self.certificate_binding.is_none() {
            self.certificate_binding = Some(handshake.binding);
        }

        Ok((cf_hash, session_hash, sf_hash_input))
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SfHashInput {
    pub(crate) sent_hs_bytes: Vec<u8>,
    pub(crate) recv_hs_bytes: Vec<u8>,
    pub(crate) sent_ch_end: usize,
    pub(crate) recv_shd_end: usize,
}

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

/// Collect the pre-CCS handshake byte stream and decode it into
/// individual handshake messages.
fn parse_handshake_stream(
    records: &[OpaqueMessage],
) -> Result<(Vec<u8>, Vec<HandshakeMessagePayload>), TlsTranscriptError> {
    let handshake_bytes = collect_handshake_bytes_pre_ccs(records);

    let mut reader = Reader::init(&handshake_bytes);
    let mut messages = Vec::new();
    while reader.any_left() {
        let msg = HandshakeMessagePayload::read_version(&mut reader, ProtocolVersion::TLSv1_2)
            .ok_or_else(|| TlsTranscriptError::parse("failed to parse handshake message"))?;
        messages.push(msg);
    }
    Ok((handshake_bytes, messages))
}

/// Validate handshake-message bounds and compute the two
/// digests `cf_hash` and `session_hash`, and the cached
/// inputs needed to derive `sf_hash` later from `cf_vd`.
fn compute_handshake_hashes(
    sent_hs_bytes: Vec<u8>,
    recv_hs_bytes: Vec<u8>,
    sent_msgs: &[HandshakeMsgInfo],
    recv_msgs: &[HandshakeMsgInfo],
) -> Result<([u8; 32], [u8; 32], SfHashInput), TlsTranscriptError> {
    let client_hello = sent_msgs
        .first()
        .ok_or_else(|| TlsTranscriptError::parse("missing ClientHello in sent handshake stream"))?;
    if client_hello.typ != HandshakeType::ClientHello {
        return Err(TlsTranscriptError::parse(
            "first sent handshake message is not ClientHello",
        ));
    }
    let ckx = sent_msgs
        .iter()
        .find(|m| m.typ == HandshakeType::ClientKeyExchange)
        .ok_or_else(|| TlsTranscriptError::parse("missing ClientKeyExchange"))?;
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

    let sent_ch_end = client_hello.end;
    let recv_shd_end = shd.end;

    // session_hash: ClientHello → server flight (ServerHello..ServerHelloDone)
    // → client flight up to and including ClientKeyExchange.
    let mut hasher = Sha256::new();
    hasher.update(&sent_hs_bytes[..sent_ch_end]);
    hasher.update(&recv_hs_bytes);
    hasher.update(&sent_hs_bytes[sent_ch_end..ckx.end]);
    let session_hash: [u8; 32] = hasher.finalize().into();

    // cf_hash: ClientHello → server first flight (..ServerHelloDone)
    // → remaining client flight (ClientKeyExchange and, when client
    // auth is active, CertificateVerify).
    let mut hasher = Sha256::new();
    hasher.update(&sent_hs_bytes[..sent_ch_end]);
    hasher.update(&recv_hs_bytes[..recv_shd_end]);
    hasher.update(&sent_hs_bytes[sent_ch_end..]);
    let cf_hash: [u8; 32] = hasher.finalize().into();

    Ok((
        cf_hash,
        session_hash,
        SfHashInput {
            sent_hs_bytes,
            recv_hs_bytes,
            sent_ch_end,
            recv_shd_end,
        },
    ))
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

/// Walk a concatenated handshake byte stream and return the
/// [`HandshakeMsgInfo`].
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

fn validate_finished_record(value: &Record) -> Result<(), TlsTranscriptError> {
    if !matches!(value.typ, ContentType::Handshake) {
        return Err(TlsTranscriptError::validation(format!(
            "first record expected to be a handshake finished message, but has type {:?}",
            value.typ
        )));
    }
    if value.seq != 0 {
        return Err(TlsTranscriptError::validation(format!(
            "first record should have sequence number 0, but has {}",
            value.seq
        )));
    }

    if let Some(payload) = &value.plaintext {
        let mut reader = Reader::init(payload);
        let payload = HandshakeMessagePayload::read_version(&mut reader, ProtocolVersion::TLSv1_2)
            .ok_or_else(|| {
                TlsTranscriptError::validation("expected finished record but record is malformed")
            })?;

        if !matches!(payload.payload, HandshakePayload::Finished(_)) {
            return Err(TlsTranscriptError::validation("expected finished record"));
        }
    }

    Ok(())
}

fn validate_seq(records: &[Record]) -> Result<(), TlsTranscriptError> {
    for pair in records.windows(2) {
        if pair[1].seq <= pair[0].seq {
            return Err(TlsTranscriptError::validation(format!(
                "records must have strictly increasing sequence numbers, but got {} after {}",
                pair[1].seq, pair[0].seq,
            )));
        }
    }
    Ok(())
}

/// Parses records and adds plaintext to application data records.
fn parse_records(
    records: &[OpaqueMessage],
    app_data: Option<&[u8]>,
) -> Result<Vec<Record>, TlsTranscriptError> {
    let mut parsed = Vec::new();

    // Parse finished record.
    let ccs = records
        .iter()
        .position(|r| r.typ == TlsContentType::ChangeCipherSpec)
        .ok_or_else(|| TlsTranscriptError::missing("ccs record is missing"))?;
    let raw_finished = records
        .get(ccs + 1)
        .ok_or_else(|| TlsTranscriptError::parse("missing Finished record after CCS"))?;

    let payload = &raw_finished.payload.0;
    if payload.len() < NONCE_LEN + TAG_LEN {
        return Err(TlsTranscriptError::parse("encrypted record too short"));
    }

    let typ = raw_finished.typ.into();
    if !matches!(typ, ContentType::Handshake) {
        return Err(TlsTranscriptError::validation(format!(
            "expected content type handshake for finished record, but got {:?}",
            typ
        )));
    }

    let finished_record = Record {
        seq: 0,
        typ: ContentType::Handshake,
        plaintext: None,
        explicit_nonce: payload[..NONCE_LEN].to_vec(),
        ciphertext: payload[NONCE_LEN..payload.len() - TAG_LEN].to_vec(),
        tag: Some(payload[payload.len() - TAG_LEN..].to_vec()),
    };
    parsed.push(finished_record);

    // Now parse app data and skip CCS and the Finished record.
    let mut consumed = 0;
    for (seq, record) in (1u64..).zip(records.iter().skip(ccs + 2)) {
        let mut rec = split_into_record(seq, &record.payload.0, record.typ)?;

        if rec.typ == ContentType::ApplicationData
            && let Some(app_data) = app_data
        {
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

    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tls_server_fixture::SERVER_CERT_DER;

    // Pre-generated TLS 1.2 transcript fixtures. Captured once from a real
    // handshake against `tls_server_fixture::bind_test_server` followed by
    // four `msgN` records (each padded to 1024 bytes) echoed as "hello".
    // The server certificate is `tls_server_fixture::SERVER_CERT_DER`, so
    // regenerate these files if that cert ever changes.
    const SENT: &[u8] = include_bytes!("../fixtures/tls_sent.bin");
    const RECV: &[u8] = include_bytes!("../fixtures/tls_recv.bin");
    const APP_SENT: &[u8] = include_bytes!("../fixtures/tls_app_sent.bin");
    const APP_RECV: &[u8] = include_bytes!("../fixtures/tls_app_recv.bin");
    const MSG_COUNT: usize = 4;

    #[test]
    fn test_parse_handshake() {
        let transcript = TlsTranscript::builder()
            .time(0)
            .tls_sent(SENT)
            .tls_recv(RECV)
            .build()
            .unwrap();

        assert_eq!(transcript.version(), TlsVersion::V1_2);

        // Certificate chain should contain the server cert.
        let certs = transcript.server_cert_chain().expect("cert chain parsed");
        assert_eq!(certs[0].0, SERVER_CERT_DER);

        // Signature algorithm should be an RSA variant.
        let alg = &transcript.server_signature().expect("signature parsed").alg;
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
        let sent_records = parse_records(&sent_raw, Some(APP_SENT)).unwrap();
        let recv_records = parse_records(&recv_raw, Some(APP_RECV)).unwrap();

        // Sent records: 5 messages, finshed record and 4 app records
        assert_eq!(sent_records.len(), MSG_COUNT + 1);
        for (i, record) in sent_records.iter().enumerate() {
            let expected_seq = (i) as u64;
            if i == 0 {
                assert_eq!(record.typ, ContentType::Handshake);
            } else {
                assert_eq!(record.typ, ContentType::ApplicationData);
            }
            assert_eq!(record.seq, expected_seq);
            assert_eq!(record.explicit_nonce.len(), 8);
            assert!(!record.ciphertext.is_empty());
            assert_eq!(record.tag.as_ref().unwrap().len(), 16);
        }

        // Recv records: 5 messages, finshed record and 4 app records
        assert_eq!(recv_records.len(), MSG_COUNT + 1);
        for (i, record) in recv_records.iter().enumerate() {
            let expected_seq = (i) as u64;
            assert_eq!(record.seq, expected_seq);
            if i == 0 {
                assert_eq!(record.typ, ContentType::Handshake);
            } else {
                assert_eq!(record.typ, ContentType::ApplicationData);
            }
            assert_eq!(record.explicit_nonce.len(), 8);
            assert!(!record.ciphertext.is_empty());
            assert_eq!(record.tag.as_ref().unwrap().len(), 16);
        }
    }

    #[test]
    fn test_parse_into_transcript() {
        let transcript = TlsTranscript::builder()
            .time(0)
            .tls_sent(SENT)
            .tls_recv(RECV)
            .app_sent(APP_SENT)
            .app_recv(APP_RECV)
            .build()
            .unwrap();

        assert_eq!(transcript.version(), TlsVersion::V1_2);
        assert!(transcript.server_cert_chain().is_some());
        assert!(transcript.server_signature().is_some());

        // Finished verify-data records have content type Handshake.
        assert!(!transcript.client_finished().ciphertext.is_empty());
        assert!(!transcript.server_finished().ciphertext.is_empty());

        // 1 finished record and 4 app data records each
        assert_eq!(transcript.sent().len(), MSG_COUNT + 1);
        assert_eq!(transcript.recv().len(), MSG_COUNT + 1);
        assert_eq!(transcript.sent()[0].seq, 0);
        assert_eq!(transcript.recv()[0].seq, 0);
    }
}
