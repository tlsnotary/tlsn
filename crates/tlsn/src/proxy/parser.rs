use std::fmt::Display;
use thiserror::Error;
use tls_parser::{
    ECParametersContent, NamedGroup, SignatureAndHashAlgorithm, TlsMessage, TlsMessageHandshake,
    TlsRawRecord, TlsRecordType, parse_content_and_signature, parse_ecdh_params,
    parse_tls_message_handshake, parse_tls_raw_record,
};
use tlsn_core::{
    connection::{
        CertBinding, CertBindingV1_2, HandshakeData, KeyType, ServerEphemKey, ServerSignature,
        SignatureAlgorithm, TlsVersion, VerifyData,
    },
    transcript::{ContentType, Record, TlsTranscript, TlsTranscriptError},
    webpki::CertificateDer,
};

use crate::Role;

const CCS: TlsRecordType = TlsRecordType(0x14);
const ALERT: TlsRecordType = TlsRecordType(0x15);
const HANDSHAKE: TlsRecordType = TlsRecordType(0x16);
const APP_DATA: TlsRecordType = TlsRecordType(0x17);
const HEARTBEAT: TlsRecordType = TlsRecordType(0x18);

/// Records raw TLS bytes for both directions.
///
/// Currently only supports TLS 1.2 with AES-GCM.
#[derive(Debug)]
pub(crate) struct TlsParser {
    role: Role,
    time: Option<u64>,
    tls_sent: Vec<u8>,
    tls_recv: Vec<u8>,
    cf_vd: Vec<u8>,
    sf_vd: Vec<u8>,
    sent_app_data: Vec<u8>,
    recv_app_data: Vec<u8>,
}

impl TlsParser {
    pub(crate) fn new(role: Role) -> Self {
        Self {
            role,
            time: None,
            tls_sent: Vec::new(),
            tls_recv: Vec::new(),
            cf_vd: Vec::new(),
            sf_vd: Vec::new(),
            sent_app_data: Vec::new(),
            recv_app_data: Vec::new(),
        }
    }
    /// Sets the time.
    pub(crate) fn set_time(&mut self, time: u64) {
        self.time = Some(time);
    }

    /// Sets the client_finished_verify_data.
    pub(crate) fn set_cf_vd(&mut self, cf_vd: &[u8]) {
        self.cf_vd = cf_vd.to_vec();
    }

    /// Sets the server_finished_verify_data.
    pub(crate) fn set_sf_vd(&mut self, sf_vd: &[u8]) {
        self.sf_vd = sf_vd.to_vec();
    }

    /// Append tls bytes sent to the server.
    pub(crate) fn extend_tls_sent(&mut self, data: &[u8]) {
        self.tls_sent.extend(data);
    }

    /// Append tls bytes received from the server.
    pub(crate) fn extend_tls_recv(&mut self, data: &[u8]) {
        self.tls_recv.extend(data);
    }

    /// Returns mutable references to the raw TLS byte buffers for both
    /// directions.
    pub(crate) fn tls_buffers_mut(&mut self) -> (&mut Vec<u8>, &mut Vec<u8>) {
        (&mut self.tls_sent, &mut self.tls_recv)
    }

    /// Append plaintext application bytes sent to the server.
    pub(crate) fn extend_app_sent(&mut self, data: &[u8]) {
        self.sent_app_data.extend(data);
    }

    /// Returns the received app data.
    pub(crate) fn mut_app_recv(&mut self) -> &mut Vec<u8> {
        &mut self.recv_app_data
    }

    pub(crate) fn parse_handshake(&mut self) -> Result<HandshakeData, TlsParserError> {
        let sent_raw_records = parse_raw_records(&self.tls_sent)?;
        let recv_raw_records = parse_raw_records(&self.tls_recv)?;

        let (_, handshake) = parse_handshake(&sent_raw_records, &recv_raw_records)?;
        Ok(handshake)
    }

    /// Creates the `TlsTranscript`.
    pub(crate) fn build(&self) -> Result<TlsTranscript, TlsParserError> {
        let Some(time) = self.time else {
            return Err(TlsParserError::missing().with_msg("time should have been set"));
        };

        if self.cf_vd.is_empty() {
            return Err(TlsParserError::missing()
                .with_msg("client_finished_verify_data should have been set"));
        }

        if self.sf_vd.is_empty() {
            return Err(TlsParserError::missing()
                .with_msg("server_finished_verify_data should have been set"));
        }

        let sent_raw_records = parse_raw_records(&self.tls_sent)?;
        let recv_raw_records = parse_raw_records(&self.tls_recv)?;

        let (version, handshake) = parse_handshake(&sent_raw_records, &recv_raw_records)?;

        let client_finished_record = parse_verify_data(&sent_raw_records, &self.cf_vd)?;
        let server_finished_record = parse_verify_data(&recv_raw_records, &self.sf_vd)?;

        let verify_data = VerifyData {
            client_finished: self.cf_vd.to_vec(),
            server_finished: self.sf_vd.to_vec(),
        };

        let mut sent_records = vec![client_finished_record];
        sent_records.extend(parse_app_records(
            self.role,
            &sent_raw_records,
            &self.sent_app_data,
        )?);

        let mut recv_records = vec![server_finished_record];
        recv_records.extend(parse_app_records(
            self.role,
            &recv_raw_records,
            &self.recv_app_data,
        )?);

        let transcript = TlsTranscript::new(
            time,
            version,
            Some(handshake.certs),
            Some(handshake.sig),
            handshake.binding,
            verify_data,
            sent_records,
            recv_records,
        )?;

        Ok(transcript)
    }
}

fn parse_app_records(
    role: Role,
    raw_records: &[TlsRawRecord],
    app_data: &[u8],
) -> Result<Vec<Record>, TlsParserError> {
    let mut seq = 1;
    let mut consumed = 0;
    let mut parsed_app_records = Vec::new();

    if let Some(start) = find_ccs(raw_records) {
        // Skip the CCS and Finished handshake message by adding 2.
        for record in raw_records
            .iter()
            .skip(start + 2)
            .filter(|record| record.hdr.record_type == APP_DATA)
        {
            let mut record = split_into_record(seq as u64, record.data, &record.hdr.record_type)?;

            if let Role::Prover = role {
                let cipher_len = record.ciphertext.len();
                if app_data[consumed..].len() >= cipher_len {
                    let plaintext = app_data[consumed..consumed + cipher_len].to_vec();

                    record.plaintext = Some(plaintext);
                    consumed += cipher_len;
                } else {
                    return Err(TlsParserError::parse().with_msg("insufficient plaintext data"));
                }
            }
            parsed_app_records.push(record);
            seq += 1;
        }
    }

    Ok(parsed_app_records)
}

fn parse_handshake(
    sent_records: &[TlsRawRecord],
    recv_records: &[TlsRawRecord],
) -> Result<(TlsVersion, HandshakeData), TlsParserError> {
    let mut sent_raw = Vec::new();
    for record in sent_records.iter() {
        if record.hdr.record_type == CCS {
            break;
        }
        if record.hdr.record_type == HANDSHAKE {
            sent_raw.extend_from_slice(record.data);
        }
    }
    let sent_handshake = assemble_handshake(&sent_raw)?;

    let mut recv_raw = Vec::new();
    for record in recv_records.iter() {
        if record.hdr.record_type == CCS {
            break;
        }
        if record.hdr.record_type == HANDSHAKE {
            recv_raw.extend_from_slice(record.data);
        }
    }
    let recv_handshake = assemble_handshake(&recv_raw)?;

    let version = parse_version(&recv_handshake)?;
    let client_random = parse_client_random(&sent_handshake)?;
    let server_random = parse_server_random(&recv_handshake)?;
    let certs = parse_cert_der(&recv_handshake)?;
    let (server_ephemeral_key, signature) = parse_server_key_exchange(&recv_handshake)?;

    let binding = CertBinding::V1_2(CertBindingV1_2 {
        client_random,
        server_random,
        server_ephemeral_key,
    });

    let handshake = HandshakeData {
        certs,
        sig: signature,
        binding,
    };

    Ok((version, handshake))
}

fn parse_verify_data(
    records: &[TlsRawRecord],
    verify_data: &[u8],
) -> Result<Record, TlsParserError> {
    let ccs = find_ccs(records).expect("CCS should be present");

    let raw_finished = &records[ccs + 1];
    let mut finished_record =
        split_into_record(0, raw_finished.data, &raw_finished.hdr.record_type)?;

    // 0x14 is the type for handshhake finished message
    // 0x00, 0x00, 0x0C encodes decimal 12 for 12 bytes of verify_data
    let mut finished_plain = [0x14, 0x00, 0x00, 0x0C].to_vec();
    finished_plain.extend_from_slice(verify_data);

    finished_record.plaintext = Some(finished_plain);

    Ok(finished_record)
}

fn parse_raw_records<'a>(bytes: &'a [u8]) -> Result<Vec<TlsRawRecord<'a>>, TlsParserError> {
    let mut remaining = bytes;
    let mut records = Vec::new();

    loop {
        match parse_tls_raw_record(remaining) {
            Ok((rem, record)) => {
                remaining = rem;
                records.push(record);
            }
            Err(tls_parser::nom::Err::Incomplete(_)) => break,
            Err(err) => return Err(TlsParserError::parse().with_source(err.to_string())),
        }
    }

    Ok(records)
}

fn assemble_handshake<'a>(
    handshake_bytes: &'a [u8],
) -> Result<Vec<TlsMessageHandshake<'a>>, TlsParserError> {
    let mut remaining = handshake_bytes;
    let mut messages = Vec::new();

    loop {
        match parse_tls_message_handshake(remaining) {
            Ok((rem, msg)) => {
                remaining = rem;
                let TlsMessage::Handshake(msg) = msg else {
                    return Err(TlsParserError::parse().with_msg("parsed non-handshake bytes"));
                };
                messages.push(msg);
            }
            Err(tls_parser::nom::Err::Incomplete(_)) => break,
            Err(err) => return Err(TlsParserError::parse().with_source(err.to_string())),
        }
    }

    Ok(messages)
}

fn parse_version(recv: &[TlsMessageHandshake]) -> Result<TlsVersion, TlsParserError> {
    let server_hello = recv
        .iter()
        .find_map(|msg| match msg {
            TlsMessageHandshake::ServerHello(hello) => Some(hello),
            _ => None,
        })
        .ok_or_else(|| TlsParserError::incomplete().with_msg("missing ServerHello"))?;

    let version = match server_hello.version.0 {
        0x0303 => TlsVersion::V1_2,
        v => {
            return Err(
                TlsParserError::parse().with_msg(format!("unsupported TLS version: 0x{v:04x}"))
            );
        }
    };

    Ok(version)
}

fn parse_client_random(sent: &[TlsMessageHandshake]) -> Result<[u8; 32], TlsParserError> {
    let client_hello = sent
        .iter()
        .find_map(|msg| match msg {
            TlsMessageHandshake::ClientHello(hello) => Some(hello),
            _ => None,
        })
        .ok_or_else(|| TlsParserError::incomplete().with_msg("missing ClientHello"))?;

    let client_random: [u8; 32] = client_hello
        .random
        .try_into()
        .map_err(|_| TlsParserError::unsupported().with_msg("invalid client random length"))?;

    Ok(client_random)
}

fn parse_server_random(recv: &[TlsMessageHandshake]) -> Result<[u8; 32], TlsParserError> {
    let server_hello = recv
        .iter()
        .find_map(|msg| match msg {
            TlsMessageHandshake::ServerHello(hello) => Some(hello),
            _ => None,
        })
        .ok_or_else(|| TlsParserError::incomplete().with_msg("missing ServerHello"))?;

    let server_random: [u8; 32] = server_hello
        .random
        .try_into()
        .map_err(|_| TlsParserError::unsupported().with_msg("invalid server random length"))?;

    Ok(server_random)
}

fn parse_cert_der(recv: &[TlsMessageHandshake]) -> Result<Vec<CertificateDer>, TlsParserError> {
    let cert_contents = recv
        .iter()
        .find_map(|msg| match msg {
            TlsMessageHandshake::Certificate(certs) => Some(certs),
            _ => None,
        })
        .ok_or_else(|| TlsParserError::incomplete().with_msg("missing Certificate"))?;

    let certs: Vec<CertificateDer> = cert_contents
        .cert_chain
        .iter()
        .map(|raw| CertificateDer(raw.data.to_vec()))
        .collect();

    Ok(certs)
}

fn parse_server_key_exchange(
    recv: &[TlsMessageHandshake],
) -> Result<(ServerEphemKey, ServerSignature), TlsParserError> {
    let server_key_exchange = recv
        .iter()
        .find_map(|msg| match msg {
            TlsMessageHandshake::ServerKeyExchange(ske) => Some(ske),
            _ => None,
        })
        .ok_or_else(|| TlsParserError::incomplete().with_msg("missing ServerKeyExchange"))?;

    let (_, (curve, signature)) =
        parse_content_and_signature(server_key_exchange.parameters, parse_ecdh_params, true)
            .map_err(|err| TlsParserError::parse().with_source(err.to_string()))?;

    let key_type = match &curve.curve_params.params_content {
        ECParametersContent::NamedGroup(group) if *group == NamedGroup::Secp256r1 => {
            KeyType::SECP256R1
        }
        _ => return Err(TlsParserError::unsupported().with_msg("unsupported key exchange group")),
    };

    let key = ServerEphemKey {
        typ: key_type,
        key: curve.public.point.to_vec(),
    };

    let SignatureAndHashAlgorithm { hash, sign } = signature
        .alg
        .ok_or_else(|| TlsParserError::parse().with_msg("missing signature algorithm"))?;
    let alg = match (hash.0, sign.0) {
        (4, 1) => Ok(SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA256),
        (5, 1) => Ok(SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA384),
        (6, 1) => Ok(SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA512),
        (4, 3) => Ok(SignatureAlgorithm::ECDSA_NISTP256_SHA256),
        (5, 3) => Ok(SignatureAlgorithm::ECDSA_NISTP384_SHA384),
        (8, 4) => Ok(SignatureAlgorithm::RSA_PSS_2048_8192_SHA256_LEGACY_KEY),
        (8, 5) => Ok(SignatureAlgorithm::RSA_PSS_2048_8192_SHA384_LEGACY_KEY),
        (8, 6) => Ok(SignatureAlgorithm::RSA_PSS_2048_8192_SHA512_LEGACY_KEY),
        _ => Err(TlsParserError::unsupported().with_msg(format!(
            "unsupported signature algorithm: hash={}, sign={}",
            hash.0, sign.0
        ))),
    }?;

    let signature = ServerSignature {
        alg,
        sig: signature.data.to_vec(),
    };

    Ok((key, signature))
}

/// Returns the index of the first encrypted record.
fn find_ccs(records: &[TlsRawRecord]) -> Option<usize> {
    let ccs = records.iter().position(|r| r.hdr.record_type == CCS)?;
    Some(ccs)
}

fn split_into_record(seq: u64, data: &[u8], typ: &TlsRecordType) -> Result<Record, TlsParserError> {
    const TAG_LEN: usize = 16;
    const NONCE_LEN: usize = 8;

    // we do not support handshake and ccs records here
    let typ = match *typ {
        CCS => ContentType::ChangeCipherSpec,
        HANDSHAKE => ContentType::Handshake,
        HEARTBEAT => ContentType::Heartbeat,
        ALERT => ContentType::Alert,
        APP_DATA => ContentType::ApplicationData,
        typ => {
            return Err(TlsParserError::unsupported().with_msg(format!(
                "unsupported record type: record parsing for type {typ} is not supported"
            )));
        }
    };

    if data.len() < NONCE_LEN + TAG_LEN {
        return Err(TlsParserError::parse().with_msg("encrypted record too short"));
    }

    Ok(Record {
        seq,
        typ,
        plaintext: None,
        explicit_nonce: data[..NONCE_LEN].to_vec(),
        ciphertext: data[NONCE_LEN..data.len() - TAG_LEN].to_vec(),
        tag: Some(data[data.len() - TAG_LEN..].to_vec()),
    })
}

#[derive(Debug, Error)]
pub(crate) struct TlsParserError {
    kind: ErrorKind,
    msg: Option<String>,
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl TlsParserError {
    pub(crate) fn with_msg(mut self, msg: impl Into<String>) -> Self {
        self.msg = Some(msg.into());
        self
    }

    pub(crate) fn with_source<T>(mut self, source: T) -> Self
    where
        T: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        self.source = Some(source.into());
        self
    }

    pub(crate) fn incomplete() -> Self {
        Self {
            kind: ErrorKind::Incomplete,
            msg: None,
            source: None,
        }
    }

    pub(crate) fn parse() -> Self {
        Self {
            kind: ErrorKind::Parse,
            msg: None,
            source: None,
        }
    }

    pub(crate) fn unsupported() -> Self {
        Self {
            kind: ErrorKind::Unsupported,
            msg: None,
            source: None,
        }
    }

    pub(crate) fn missing() -> Self {
        Self {
            kind: ErrorKind::Missing,
            msg: None,
            source: None,
        }
    }
}

impl From<TlsTranscriptError> for TlsParserError {
    fn from(value: TlsTranscriptError) -> Self {
        Self {
            kind: ErrorKind::Transcript,
            msg: None,
            source: Some(Box::new(value)),
        }
    }
}

impl Display for TlsParserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TlsParserError: ")?;

        match self.kind {
            ErrorKind::Parse => write!(f, "parse error")?,
            ErrorKind::Incomplete => write!(f, "incomplete transcript")?,
            ErrorKind::Transcript => write!(f, "transcript error")?,
            ErrorKind::Unsupported => write!(f, "unsupported")?,
            ErrorKind::Missing => write!(f, "missing field")?,
        }

        if let Some(msg) = &self.msg {
            write!(f, ": {msg}")?;
        }

        if let Some(source) = &self.source {
            write!(f, " caused by: {source}")?;
        }

        Ok(())
    }
}

#[derive(Debug)]
pub(crate) enum ErrorKind {
    Parse,
    Incomplete,
    Transcript,
    Unsupported,
    Missing,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::ClientConnection;
    use std::{
        io::{Read, Write},
        sync::Arc,
    };
    use tls_server_fixture::{CA_CERT_DER, SERVER_CERT_DER, SERVER_DOMAIN};
    use tokio_util::{compat::TokioAsyncReadCompatExt, io::SyncIoBridge};

    #[tokio::test]
    async fn test_parse_handshake() {
        let (client_socket, server_socket) = tokio::io::duplex(2 << 16);
        tokio::spawn(tls_server_fixture::bind_test_server(server_socket.compat()));

        let config = make_client_config();
        let server_name = rustls_pki_types::ServerName::try_from(SERVER_DOMAIN).unwrap();

        let (version, handshake) = tokio::task::spawn_blocking(move || {
            let mut stream = RecordingStream::new(SyncIoBridge::new(client_socket));
            let mut conn = ClientConnection::new(config, server_name.to_owned()).unwrap();

            let _ = do_handshake_and_io(&mut stream, &mut conn, &[]);

            let sent_records = parse_raw_records(&stream.sent).unwrap();
            let recv_records = parse_raw_records(&stream.recv).unwrap();
            parse_handshake(&sent_records, &recv_records).unwrap()
        })
        .await
        .unwrap();

        assert_eq!(version, TlsVersion::V1_2);

        // Certificate chain should contain the server cert.
        assert_eq!(handshake.certs[0].0, SERVER_CERT_DER);

        // Signature algorithm should be an RSA variant.
        let alg = &handshake.sig.alg;
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
        let CertBinding::V1_2(ref binding) = handshake.binding else {
            panic!("expected CertBinding::V1_2");
        };
        assert_ne!(binding.client_random, [0u8; 32]);
        assert_ne!(binding.server_random, [0u8; 32]);
        assert_eq!(binding.server_ephemeral_key.typ, KeyType::SECP256R1);
        // Uncompressed EC point: 65 bytes, starts with 0x04.
        assert_eq!(binding.server_ephemeral_key.key.len(), 65);
        assert_eq!(binding.server_ephemeral_key.key[0], 0x04);
    }

    #[tokio::test]
    async fn test_parse_app_records() {
        let (client_socket, server_socket) = tokio::io::duplex(2 << 16);
        tokio::spawn(tls_server_fixture::bind_test_server(server_socket.compat()));

        let config = make_client_config();
        let server_name = rustls_pki_types::ServerName::try_from(SERVER_DOMAIN).unwrap();

        let messages: &[&[u8]] = &[b"msg1", b"msg2", b"msg3"];

        let (sent_records, recv_records) = tokio::task::spawn_blocking(move || {
            let mut stream = RecordingStream::new(SyncIoBridge::new(client_socket));
            let mut conn = ClientConnection::new(config, server_name.to_owned()).unwrap();

            let (app_sent, app_recv) = do_handshake_and_io(&mut stream, &mut conn, messages);

            let sent_raw = parse_raw_records(&stream.sent).unwrap();
            let recv_raw = parse_raw_records(&stream.recv).unwrap();
            let sent_records = parse_app_records(Role::Prover, &sent_raw, &app_sent).unwrap();
            let recv_records = parse_app_records(Role::Prover, &recv_raw, &app_recv).unwrap();

            (sent_records, recv_records)
        })
        .await
        .unwrap();

        // Sent records: 3 messages, seq 1..=3.
        assert_eq!(sent_records.len(), 3);
        for (i, record) in sent_records.iter().enumerate() {
            let expected_seq = (i + 1) as u64;
            assert_eq!(record.seq, expected_seq);
            assert_eq!(record.typ, ContentType::ApplicationData);
            assert_eq!(record.explicit_nonce.len(), 8);
            assert!(!record.ciphertext.is_empty());
            assert_eq!(record.tag.as_ref().unwrap().len(), 16);

            let plaintext = record.plaintext.as_ref().expect("plaintext should be set");
            assert!(plaintext.starts_with(messages[i]));
        }

        // Recv records: 3 "hello" responses, seq 1..=3.
        assert_eq!(recv_records.len(), 3);
        for (i, record) in recv_records.iter().enumerate() {
            let expected_seq = (i + 1) as u64;
            assert_eq!(record.seq, expected_seq);
            assert_eq!(record.typ, ContentType::ApplicationData);
            assert_eq!(record.explicit_nonce.len(), 8);
            assert!(!record.ciphertext.is_empty());
            assert_eq!(record.tag.as_ref().unwrap().len(), 16);

            let plaintext = record.plaintext.as_ref().expect("plaintext should be set");
            assert_eq!(plaintext, b"hello");
        }
    }

    #[tokio::test]
    async fn test_into_transcript() {
        let (client_socket, server_socket) = tokio::io::duplex(2 << 16);
        tokio::spawn(tls_server_fixture::bind_test_server(server_socket.compat()));

        let config = make_client_config();
        let server_name = rustls_pki_types::ServerName::try_from(SERVER_DOMAIN).unwrap();

        let messages: Vec<&[u8]> = vec![b"msg1", b"msg2", b"msg3", b"msg4"];

        let transcript = tokio::task::spawn_blocking(move || {
            let mut stream = RecordingStream::new(SyncIoBridge::new(client_socket));
            let mut conn = ClientConnection::new(config, server_name.to_owned()).unwrap();

            let (app_sent, app_recv) =
                do_handshake_and_io(&mut stream, &mut conn, messages.as_slice());

            let mut parser = TlsParser::new(Role::Prover);
            let now = web_time::UNIX_EPOCH
                .elapsed()
                .expect("system time is available")
                .as_secs();
            parser.set_time(now);
            parser.extend_tls_sent(&stream.sent);
            parser.extend_tls_recv(&stream.recv);
            parser.extend_app_sent(&app_sent);
            parser.mut_app_recv().extend_from_slice(&app_recv);

            let cf_vd = vec![0xAAu8; 12];
            let sf_vd = vec![0xBBu8; 12];

            parser.set_cf_vd(&cf_vd);
            parser.set_sf_vd(&sf_vd);
            parser.build().unwrap()
        })
        .await
        .unwrap();

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

    /// Sync `Read + Write` wrapper that records all bytes flowing through.
    struct RecordingStream<S> {
        inner: S,
        sent: Vec<u8>,
        recv: Vec<u8>,
    }

    impl<S> RecordingStream<S> {
        fn new(inner: S) -> Self {
            Self {
                inner,
                sent: Vec::new(),
                recv: Vec::new(),
            }
        }
    }

    impl<S: Read> Read for RecordingStream<S> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.inner.read(buf)?;
            self.recv.extend_from_slice(&buf[..n]);
            Ok(n)
        }
    }

    impl<S: Write> Write for RecordingStream<S> {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let n = self.inner.write(buf)?;
            self.sent.extend_from_slice(&buf[..n]);
            Ok(n)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.inner.flush()
        }
    }

    fn make_client_config() -> Arc<rustls::ClientConfig> {
        let mut root_store = rustls::RootCertStore::empty();
        let ca = rustls_pki_types::CertificateDer::from(CA_CERT_DER);
        root_store.add(ca).unwrap();

        let default_provider = rustls::crypto::aws_lc_rs::default_provider();
        let kx_groups = default_provider
            .kx_groups
            .iter()
            .filter(|g| g.name() == rustls::NamedGroup::secp256r1)
            .cloned()
            .collect();
        let provider = rustls::crypto::CryptoProvider {
            kx_groups,
            ..default_provider
        };

        let config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Arc::new(config)
    }

    /// Perform a TLS handshake and optionally exchange app data.
    /// Returns (plaintext_sent, plaintext_recv).
    fn do_handshake_and_io(
        stream: &mut RecordingStream<SyncIoBridge<tokio::io::DuplexStream>>,
        conn: &mut ClientConnection,
        messages: &[&[u8]],
    ) -> (Vec<u8>, Vec<u8>) {
        // Complete the handshake.
        conn.complete_io(stream).unwrap();

        let mut app_sent = Vec::new();
        let mut app_recv = Vec::new();

        for msg in messages {
            // Pad message to APP_RECORD_LENGTH (1024 bytes) as the server expects.
            let mut padded = vec![0u8; 1024];
            padded[..msg.len()].copy_from_slice(msg);

            conn.writer().write_all(&padded).unwrap();
            app_sent.extend_from_slice(&padded);
            conn.complete_io(stream).unwrap();

            // Read the "hello" response from the server.
            conn.complete_io(stream).unwrap();
            let mut buf = vec![0u8; 1024];
            let n = conn.reader().read(&mut buf).unwrap();
            assert!(n > 0, "expected server response");
            app_recv.extend_from_slice(&buf[..n]);
        }

        (app_sent, app_recv)
    }
}
