//! TLS connection I/O and framing.
//!
//! This module factors the connection plumbing that is shared by both phases of
//! a live connection (handshaking and online) out of the leader's state:
//!
//! * [`TlsIo`] owns the pure TLS framing state — record (de)framing, message
//!   fragmentation, the plaintext/ciphertext buffers and the record-protection
//!   gates — with the methods that touch only framing.
//! * [`Conn`] bundles [`TlsIo`] with the [`MpcSession`] and provides the
//!   operations that need both: encrypting/decrypting records through MPC,
//!   sending wire messages to the follower, alerts, and the verify-data
//!   computations.
//!
//! The handshake-phase-specific state (the handshake state machine, the
//! handshake joiner, client config) lives in the leader's `Handshaking` phase,
//! not here.

use std::{collections::VecDeque, io};

use serio::SinkExt;
use tls_core::{
    cert::ServerCertDetails,
    ke::ServerKxDetails,
    key::PublicKey,
    msgs::{
        alert::AlertMessagePayload,
        base::Payload,
        deframer::MessageDeframer,
        enums::{AlertDescription, AlertLevel, ContentType, NamedGroup, ProtocolVersion},
        fragmenter::MessageFragmenter,
        handshake::Random,
        hsjoiner::HandshakeJoiner,
        message::{Message, OpaqueMessage, PlainMessage},
    },
    suites::SupportedCipherSuite,
};
use tracing::{debug, error, instrument, warn};

use crate::{
    MpcTlsError,
    handshake::error::Error,
    msg::{Decrypt, Encrypt, Message as MpcMessage, ServerHello},
    session::{MpcSession, opaque_into_parts},
    vecbuf::ChunkVecBuffer,
};

const DEFAULT_BUFFER_LIMIT: usize = 64 * 1024;

/// How many ChangeCipherSpec messages we accept and drop in TLS1.3 handshakes.
/// The spec says 1, but implementations (namely the boringssl test suite) get
/// this wrong. BoringSSL itself accepts up to 32.
pub(crate) const TLS13_MAX_DROPPED_CCS: u8 = 2;

/// Values returned from `process_new_packets` describing the current I/O state
/// of the connection.
#[derive(Debug, PartialEq)]
pub struct IoState {
    tls_bytes_to_write: usize,
    plaintext_bytes_to_read: usize,
}

impl IoState {
    /// How many bytes could be written by `write_tls` right now.
    pub fn tls_bytes_to_write(&self) -> usize {
        self.tls_bytes_to_write
    }

    /// How many plaintext bytes could be read via `read_plaintext` without
    /// further I/O.
    pub fn plaintext_bytes_to_read(&self) -> usize {
        self.plaintext_bytes_to_read
    }
}

/// The client and server randoms of a connection.
#[derive(Debug)]
pub(crate) struct ConnectionRandoms {
    pub(crate) client: [u8; 32],
    pub(crate) server: [u8; 32],
}

impl ConnectionRandoms {
    pub(crate) fn new(client: Random, server: Random) -> Self {
        Self {
            client: client.0,
            server: server.0,
        }
    }
}

/// Returns whether `msg` is a valid (unencrypted) ChangeCipherSpec record.
pub(crate) fn is_valid_ccs(msg: &OpaqueMessage) -> bool {
    // nb. this is prior to the record layer, so is unencrypted. see
    // third paragraph of section 5 in RFC8446.
    msg.typ == ContentType::ChangeCipherSpec && msg.payload.0 == [0x01]
}

/// TLS framing state shared by both connection phases.
pub(crate) struct TlsIo {
    /// The negotiated protocol version.
    pub(crate) negotiated_version: Option<ProtocolVersion>,
    /// The negotiated cipher suite.
    pub(crate) suite: Option<SupportedCipherSuite>,
    /// The negotiated ALPN protocol.
    pub(crate) alpn_protocol: Option<Vec<u8>>,
    /// Whether outgoing records are encrypted, activated by the CCS we send.
    encrypting: bool,
    /// Whether incoming records are decrypted, activated by the server's CCS.
    decrypting: bool,
    sent_fatal_alert: bool,
    has_received_close_notify: bool,
    /// Whether the last processed handshake flight was aligned (no pending
    /// fragment). Changing keys must not span a fragmented handshake message.
    aligned_handshake: bool,
    /// Count of middlebox-compatibility CCS records dropped during a TLS 1.3
    /// handshake.
    received_middlebox_ccs: u8,
    message_fragmenter: MessageFragmenter,
    message_deframer: MessageDeframer,
    handshake_joiner: HandshakeJoiner,
    received_plaintext: ChunkVecBuffer,
    sendable_plaintext: ChunkVecBuffer,
    sendable_tls: ChunkVecBuffer,
}

impl TlsIo {
    /// Creates the framing state, validating the configured fragment size.
    pub(crate) fn new(max_fragment_size: Option<usize>) -> Result<Self, Error> {
        Ok(Self {
            negotiated_version: None,
            suite: None,
            alpn_protocol: None,
            encrypting: false,
            decrypting: false,
            sent_fatal_alert: false,
            has_received_close_notify: false,
            aligned_handshake: true,
            received_middlebox_ccs: 0,
            message_fragmenter: MessageFragmenter::new(max_fragment_size)
                .map_err(|_| Error::BadMaxFragmentSize)?,
            message_deframer: MessageDeframer::new(),
            handshake_joiner: HandshakeJoiner::new(),
            received_plaintext: ChunkVecBuffer::new(Some(0)),
            sendable_plaintext: ChunkVecBuffer::new(Some(DEFAULT_BUFFER_LIMIT)),
            sendable_tls: ChunkVecBuffer::new(Some(DEFAULT_BUFFER_LIMIT)),
        })
    }

    pub(crate) fn is_tls13(&self) -> bool {
        matches!(self.negotiated_version, Some(ProtocolVersion::TLSv1_3))
    }

    pub(crate) fn decrypting(&self) -> bool {
        self.decrypting
    }

    /// Starts encrypting outgoing records. Called when we send our CCS.
    pub(crate) fn start_encrypting(&mut self) {
        self.encrypting = true;
    }

    /// Starts decrypting incoming records. Called when the server's CCS is
    /// received.
    pub(crate) fn start_decrypting(&mut self) {
        self.decrypting = true;
    }

    pub(crate) fn has_received_close_notify(&self) -> bool {
        self.has_received_close_notify
    }

    pub(crate) fn set_received_close_notify(&mut self) {
        self.has_received_close_notify = true;
    }

    pub(crate) fn deframer_desynced(&self) -> bool {
        self.message_deframer.desynced
    }

    /// Reads TLS records from `rd` into the internal buffer.
    pub(crate) fn read_tls(&mut self, rd: &mut dyn io::Read) -> io::Result<usize> {
        self.message_deframer.read(rd)
    }

    /// Writes buffered TLS records to `wr`.
    pub(crate) fn write_tls(&mut self, wr: &mut dyn io::Write) -> io::Result<usize> {
        self.sendable_tls.write_to(wr)
    }

    /// Reads out buffered plaintext received from the peer.
    pub(crate) fn read_plaintext(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.received_plaintext.read(buf)
    }

    /// Buffers plaintext to be encrypted and sent to the peer.
    pub(crate) fn write_plaintext(&mut self, buf: &[u8]) -> usize {
        if buf.is_empty() {
            // Don't send empty fragments.
            return 0;
        }
        self.sendable_plaintext.append_limited_copy(buf)
    }

    pub(crate) fn wants_write(&self) -> bool {
        !self.sendable_tls.is_empty()
    }

    pub(crate) fn plaintext_is_empty(&self) -> bool {
        self.received_plaintext.is_empty()
    }

    pub(crate) fn sendable_tls_is_empty(&self) -> bool {
        self.sendable_tls.is_empty()
    }

    pub(crate) fn sendable_plaintext_is_full(&self) -> bool {
        self.sendable_plaintext.is_full()
    }

    pub(crate) fn current_io_state(&self) -> IoState {
        IoState {
            tls_bytes_to_write: self.sendable_tls.len(),
            plaintext_bytes_to_read: self.received_plaintext.len(),
        }
    }

    pub(crate) fn next_received_frame(&mut self) -> Option<OpaqueMessage> {
        self.message_deframer.frames.pop_front()
    }

    pub(crate) fn next_sendable_plaintext(&mut self) -> Option<Vec<u8>> {
        self.sendable_plaintext.pop()
    }

    pub(crate) fn queue_tls_message(&mut self, m: OpaqueMessage) {
        self.sendable_tls.append(m.encode());
    }

    pub(crate) fn take_received_plaintext(&mut self, bytes: Payload) {
        self.received_plaintext.append(bytes.0);
    }

    pub(crate) fn aligned_handshake(&self) -> bool {
        self.aligned_handshake
    }

    pub(crate) fn received_middlebox_ccs(&self) -> u8 {
        self.received_middlebox_ccs
    }

    pub(crate) fn inc_received_middlebox_ccs(&mut self) {
        self.received_middlebox_ccs += 1;
    }

    /// Returns whether `msg` is a handshake message that must be reassembled
    /// before processing.
    pub(crate) fn joiner_wants(&self, msg: &PlainMessage) -> bool {
        self.handshake_joiner.want_message(msg)
    }

    /// Feeds a handshake message to the joiner. Returns `None` if it is
    /// malformed.
    pub(crate) fn join(&mut self, msg: PlainMessage) -> Option<()> {
        self.handshake_joiner.take_message(msg).map(|_| ())
    }

    /// Marks whether the handshake flight just joined was aligned, returning the
    /// next reassembled handshake message if any.
    pub(crate) fn mark_aligned_handshake(&mut self) {
        self.aligned_handshake = self.handshake_joiner.is_empty();
    }

    pub(crate) fn next_joined_message(&mut self) -> Option<Message> {
        self.handshake_joiner.frames.pop_front()
    }
}

/// Server parameters of the TLS handshake, collected by the client during the
/// handshake and used to build the transcript at close.
#[derive(Debug)]
pub(crate) struct HandshakeData {
    /// The server random.
    pub(crate) server_random: Random,
    /// The server ephemeral public key.
    pub(crate) server_key: PublicKey,
    /// The server certificate chain and certificate metadata.
    pub(crate) server_cert_details: ServerCertDetails,
    /// The server key exchange parameters and signature.
    pub(crate) server_kx_details: ServerKxDetails,
}

/// A live TLS connection: its I/O, its MPC session, and the facts negotiated
/// during the handshake.
///
/// `Conn` owns the framing ([`TlsIo`]) and the [`MpcSession`], and provides the
/// operations that need both: sending records (encrypting application data
/// through MPC), receiving records (queuing them for MPC decryption), alerts,
/// the Finished verify-data computations and the key derivation. It is the
/// context the handshake state machine and the online router operate on, and is
/// shared unchanged across the handshaking and online phases.
pub(crate) struct Conn {
    pub(crate) io: TlsIo,
    pub(crate) session: MpcSession,
    /// The client random, generated during setup; used in the ClientHello and
    /// in the transcript's certificate binding at close.
    pub(crate) client_random: Random,
    /// Server handshake parameters, set by [`Conn::prepare_encryption`] and
    /// used to build the transcript at close.
    pub(crate) server_params: Option<HandshakeData>,
    /// The handshake time, set by [`Conn::prepare_encryption`].
    pub(crate) time: Option<u64>,
}

impl Conn {
    pub(crate) fn new(io: TlsIo, session: MpcSession, client_random: Random) -> Self {
        Self {
            io,
            session,
            client_random,
            server_params: None,
            time: None,
        }
    }

    /// Whether the session keys have been derived and the record layer prepared.
    pub(crate) fn encryption_prepared(&self) -> bool {
        self.server_params.is_some()
    }

    /// Sends a protocol message to the follower.
    pub(crate) async fn send_message(&mut self, msg: MpcMessage) -> Result<(), MpcTlsError> {
        self.session.ctx_mut().io_mut().send(msg).await?;
        Ok(())
    }

    /// Returns the client's ephemeral public key for the key exchange.
    pub(crate) fn client_key_share(&self) -> Result<PublicKey, MpcTlsError> {
        self.session.client_key_share()
    }

    /// Computes the session keys from the server's handshake parameters and
    /// prepares the record layer for encryption.
    #[instrument(level = "debug", skip_all, err)]
    pub(crate) async fn prepare_encryption(
        &mut self,
        hs: HandshakeData,
    ) -> Result<(), MpcTlsError> {
        debug!("preparing encryption");

        if hs.server_key.group != NamedGroup::secp256r1 {
            return Err(MpcTlsError::hs("invalid server public keyshare"));
        }

        let time = web_time::UNIX_EPOCH
            .elapsed()
            .expect("system time is available")
            .as_secs();

        self.send_message(MpcMessage::ServerHello(ServerHello {
            time,
            random: hs.server_random.0,
            key: hs.server_key.clone(),
        }))
        .await?;

        let server_key =
            p256::PublicKey::from_sec1_bytes(&hs.server_key.key).map_err(MpcTlsError::hs)?;
        self.session.compute_keys(hs.server_random.0, server_key).await?;

        self.server_params = Some(hs);
        self.time = Some(time);

        debug!("encryption prepared");

        Ok(())
    }

    #[instrument(level = "debug", skip_all, err)]
    pub(crate) async fn get_client_finished_vd(
        &mut self,
        hash: Vec<u8>,
    ) -> Result<Vec<u8>, MpcTlsError> {
        debug!("computing client finished verify data");
        let hash: [u8; 32] = hash
            .try_into()
            .map_err(|_| MpcTlsError::hs("client finished handshake hash is not 32 bytes"))?;

        self.send_message(MpcMessage::ClientFinishedVd(hash)).await?;
        let vd = self.session.compute_cf_vd(hash).await?;

        Ok(vd.to_vec())
    }

    #[instrument(level = "debug", skip_all, err)]
    pub(crate) async fn get_server_finished_vd(
        &mut self,
        hash: Vec<u8>,
    ) -> Result<Vec<u8>, MpcTlsError> {
        debug!("computing server finished verify data");
        let hash: [u8; 32] = hash
            .try_into()
            .map_err(|_| MpcTlsError::hs("server finished handshake hash is not 32 bytes"))?;

        self.send_message(MpcMessage::ServerFinishedVd(hash)).await?;
        let vd = self.session.compute_sf_vd(hash).await?;

        Ok(vd.to_vec())
    }

    /// Sends a raw TLS message, fragmenting it and encrypting if required.
    pub(crate) async fn send_msg(&mut self, m: Message, must_encrypt: bool) -> Result<(), Error> {
        if !must_encrypt {
            let mut to_send = VecDeque::new();
            self.io.message_fragmenter.fragment(m.into(), &mut to_send);
            for mm in to_send {
                self.io.queue_tls_message(mm.into_unencrypted_opaque());
            }
            Ok(())
        } else {
            self.send_msg_encrypt(m.into()).await
        }
    }

    /// Fragments `m`, encrypts the fragments, and queues them for sending.
    ///
    /// Unlike upstream rustls there is no sequence-space exhaustion guard: the
    /// MPC record layer enforces the configured traffic limits, which bound the
    /// number of records far below the sequence space.
    async fn send_msg_encrypt(&mut self, m: PlainMessage) -> Result<(), Error> {
        let mut plain_messages = VecDeque::new();
        self.io.message_fragmenter.fragment(m, &mut plain_messages);

        for m in plain_messages {
            self.send_single_fragment(m).await?;
        }
        Ok(())
    }

    pub(crate) async fn send_appdata_encrypt(&mut self, payload: &[u8]) -> Result<usize, Error> {
        let mut plain_messages = VecDeque::new();
        self.io.message_fragmenter.fragment(
            PlainMessage {
                typ: ContentType::ApplicationData,
                version: ProtocolVersion::TLSv1_2,
                payload: Payload::new(payload),
            },
            &mut plain_messages,
        );

        for m in plain_messages {
            self.send_single_fragment(m).await?;
        }

        Ok(payload.len())
    }

    async fn send_single_fragment(&mut self, m: PlainMessage) -> Result<(), Error> {
        debug_assert!(self.io.encrypting);
        self.push_outgoing(m).await?;
        Ok(())
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn push_outgoing(&mut self, msg: PlainMessage) -> Result<(), Error> {
        debug!(
            "encrypting outgoing message, type: {:?}, len: {}",
            msg.typ,
            msg.payload.0.len()
        );

        let PlainMessage {
            typ,
            version,
            payload,
        } = msg;
        let plaintext = payload.0;
        let len = plaintext.len();

        // Only the contents of application data is hidden from the follower.
        let public_plaintext = match typ {
            ContentType::ApplicationData => None,
            _ => Some(plaintext.clone()),
        };

        self.session.push_encrypt(typ, version, len, Some(plaintext))?;

        self.send_message(MpcMessage::Encrypt(Encrypt {
            typ,
            version,
            len,
            plaintext: public_plaintext,
        }))
        .await?;

        Ok(())
    }

    pub(crate) async fn push_incoming(&mut self, msg: OpaqueMessage) -> Result<(), Error> {
        let OpaqueMessage {
            typ,
            version,
            payload,
        } = msg;
        let (explicit_nonce, ciphertext, tag) = opaque_into_parts(payload.0)?;

        debug!(
            "received incoming message, type: {:?}, len: {}",
            typ,
            ciphertext.len()
        );

        self.session.push_decrypt(
            typ,
            version,
            explicit_nonce.clone(),
            ciphertext.clone(),
            tag.clone(),
        )?;

        self.send_message(MpcMessage::Decrypt(Decrypt {
            typ,
            version,
            explicit_nonce,
            ciphertext,
            tag,
        }))
        .await?;

        Ok(())
    }

    pub(crate) fn next_incoming(&mut self) -> Option<PlainMessage> {
        let record = self.session.next_decrypted().map(|record| PlainMessage {
            typ: record.typ,
            version: record.version,
            payload: Payload::new(
                record
                    .plaintext
                    .expect("leader should always know plaintext"),
            ),
        });

        if let Some(record) = &record {
            debug!(
                "processing incoming message, type: {:?}, len: {}",
                record.typ,
                record.payload.0.len()
            );
        }

        record
    }

    pub(crate) fn next_outgoing(&mut self) -> Option<OpaqueMessage> {
        let record = self.session.next_encrypted().map(|record| {
            let mut payload = record.explicit_nonce;
            payload.extend_from_slice(&record.ciphertext);
            payload.extend_from_slice(&record.tag.expect("leader should always know tag"));
            OpaqueMessage {
                typ: record.typ,
                version: record.version,
                payload: Payload::new(payload),
            }
        });

        if let Some(record) = &record {
            debug!(
                "sending outgoing message, type: {:?}, len: {}",
                record.typ,
                record.payload.0.len()
            );
        }

        record
    }

    /// Sends the server's traffic-start signal and starts the record layer.
    pub(crate) async fn start_traffic(&mut self) -> Result<(), Error> {
        self.session.start_traffic();
        self.send_message(MpcMessage::StartTraffic).await?;
        Ok(())
    }

    /// Flushes the record layer if there is buffered work.
    #[instrument(level = "debug", skip_all, err)]
    pub(crate) async fn flush_records(&mut self, is_decrypting: bool) -> Result<(), Error> {
        if !self.session.wants_flush() {
            debug!("record layer is empty, skipping flush");
            return Ok(());
        }

        debug!("flushing record layer");
        self.send_message(MpcMessage::Flush { is_decrypting }).await?;
        self.session.flush(is_decrypting).await?;

        Ok(())
    }

    pub(crate) async fn send_warning_alert(&mut self, desc: AlertDescription) -> Result<(), Error> {
        warn!("Sending warning alert {:?}", desc);
        self.send_warning_alert_no_log(desc).await
    }

    async fn send_warning_alert_no_log(&mut self, desc: AlertDescription) -> Result<(), Error> {
        let m = Message::build_alert(AlertLevel::Warning, desc);
        let must_encrypt = self.io.encrypting;
        self.send_msg(m, must_encrypt).await
    }

    pub(crate) async fn send_fatal_alert(&mut self, desc: AlertDescription) -> Result<(), Error> {
        warn!("Sending fatal alert {:?}", desc);
        debug_assert!(!self.io.sent_fatal_alert);
        let m = Message::build_alert(AlertLevel::Fatal, desc);
        let must_encrypt = self.io.encrypting;
        self.send_msg(m, must_encrypt).await?;
        self.io.sent_fatal_alert = true;
        Ok(())
    }

    /// Queues a close_notify warning alert to be sent in the next `write_tls`.
    pub(crate) async fn send_close_notify(&mut self) -> Result<(), Error> {
        debug!("Sending warning alert {:?}", AlertDescription::CloseNotify);
        self.send_warning_alert_no_log(AlertDescription::CloseNotify)
            .await
    }

    /// Errors if the handshake is not aligned (a key change must not span a
    /// fragmented handshake message), sending a fatal alert.
    pub(crate) async fn check_aligned_handshake(&mut self) -> Result<(), Error> {
        if !self.io.aligned_handshake() {
            self.send_fatal_alert(AlertDescription::UnexpectedMessage)
                .await?;
            Err(Error::PeerMisbehavedError(
                "key epoch or handshake flight with pending fragment".to_string(),
            ))
        } else {
            Ok(())
        }
    }

    /// Sends an `illegal_parameter` fatal alert and returns the corresponding
    /// error.
    pub(crate) async fn illegal_param(&mut self, why: &str) -> Result<Error, Error> {
        self.send_fatal_alert(AlertDescription::IllegalParameter)
            .await?;
        Ok(Error::PeerMisbehavedError(why.to_string()))
    }

    pub(crate) async fn process_alert(&mut self, alert: &AlertMessagePayload) -> Result<(), Error> {
        if let AlertLevel::Unknown(_) = alert.level {
            self.send_fatal_alert(AlertDescription::IllegalParameter)
                .await?;
        }

        if alert.description == AlertDescription::CloseNotify {
            self.io.set_received_close_notify();
            return Ok(());
        }

        if alert.level == AlertLevel::Warning {
            if self.io.is_tls13() && alert.description != AlertDescription::UserCanceled {
                self.send_fatal_alert(AlertDescription::DecodeError).await?;
            } else {
                warn!("TLS alert warning received: {:#?}", alert);
                return Ok(());
            }
        }

        error!("TLS alert received: {:#?}", alert);
        Err(Error::AlertReceived(alert.description))
    }
}
