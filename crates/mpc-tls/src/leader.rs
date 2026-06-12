//! MPC-TLS leader.
//!
//! The leader is the unified TLS client. Unlike upstream rustls it performs no
//! cryptographic operations itself: the key exchange, the PRF and record
//! encryption/decryption are delegated to an [`MpcSession`], which executes
//! them jointly with the follower using MPC. This module drives the TLS
//! protocol itself — message framing, the handshake flow, alerts and connection
//! closure — directly against that session, with no intermediate "backend"
//! abstraction.
//!
//! [`MpcTlsLeader`] is the single public type. It has two phases, modelled by
//! the private [`State`] enum:
//!
//! * [`State::Setup`] — the connection is being allocated and preprocessed
//!   before the TLS handshake begins.
//! * [`State::Live`] — the TLS connection is being driven. The [`Live`] value
//!   owns the [`MpcSession`] together with all TLS framing state and the
//!   handshake state machine, and remains in place after the connection closes
//!   so buffered plaintext can be drained before [`MpcTlsLeader::finish`].

use std::{collections::VecDeque, convert::TryFrom, io, mem, sync::Arc};

use hmac_sha256::{MSMode, Prf, PrfConfig};
use ke::KeyExchange;
use key_exchange::{self as ke, MpcKeyExchange};
use mpz_common::{Context, Flush};
use mpz_core::Block;
use mpz_ole::{Receiver as OLEReceiver, Sender as OLESender};
use mpz_ot::{
    rcot::{RCOTReceiver, RCOTSender},
    rot::{
        any::{AnyReceiver, AnySender},
        randomize::{RandomizeRCOTReceiver, RandomizeRCOTSender},
    },
};
use mpz_share_conversion::{ShareConversionReceiver, ShareConversionSender};
use serio::SinkExt;
use tls_core::{
    cert::ServerCertDetails,
    ke::ServerKxDetails,
    key::PublicKey,
    msgs::{
        alert::AlertMessagePayload,
        base::Payload,
        deframer::MessageDeframer,
        enums::{AlertDescription, AlertLevel, ContentType, HandshakeType, ProtocolVersion},
        fragmenter::MessageFragmenter,
        handshake::Random,
        hsjoiner::HandshakeJoiner,
        message::{Message, MessagePayload, OpaqueMessage, PlainMessage},
    },
    suites::SupportedCipherSuite,
    verify::verify_sig_determine_alg,
};
use tlsn_core::{
    connection::{CertBinding, CertBindingV1_2, ServerSignature, TlsVersion},
    transcript::TlsTranscript,
    webpki::CertificateDer,
};
use tracing::{debug, error, instrument, trace, warn};

use crate::{
    Config, MpcTlsError, Role, SessionKeys, Vm,
    client::{
        ClientConfig, ServerName,
        error::Error,
        hs::{self, Handshake},
        vecbuf::ChunkVecBuffer,
    },
    msg::{Decrypt, Encrypt, Message as MpcMessage, ServerHello},
    record_layer::{RecordLayer, aead::MpcAesGcm},
    session::{MpcSession, opaque_into_parts},
};

/// How many ChangeCipherSpec messages we accept and drop in TLS1.3 handshakes.
/// The spec says 1, but implementations (namely the boringssl test suite) get
/// this wrong. BoringSSL itself accepts up to 32.
static TLS13_MAX_DROPPED_CCS: u8 = 2u8;

const DEFAULT_BUFFER_LIMIT: usize = 64 * 1024;

/// MPC-TLS leader: the unified TLS-over-MPC client.
pub struct MpcTlsLeader {
    /// Whether incoming application data is decrypted while the connection is
    /// active. Mirrored into [`Live::is_decrypting`] once the connection is
    /// live; kept here so it can be read and toggled during setup.
    is_decrypting: bool,
    state: State,
}

impl std::fmt::Debug for MpcTlsLeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MpcTlsLeader")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

/// The leader's lifecycle.
enum State {
    /// MPC resources are being allocated and preprocessed before the handshake.
    Setup(Box<Setup>),
    /// The TLS connection is being driven (and, after closure, drained).
    Live(Box<Live>),
    /// Transient poison used while transitioning between states.
    Invalid,
}

impl State {
    fn take(&mut self) -> Self {
        mem::replace(self, State::Invalid)
    }
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            State::Setup(_) => "Setup",
            State::Live(_) => "Live",
            State::Invalid => "Invalid",
        })
    }
}

/// Pre-handshake state: the MPC session being allocated and preprocessed.
struct Setup {
    config: Config,
    session: MpcSession,
    client_random: Random,
}

impl MpcTlsLeader {
    /// Creates a new leader instance.
    pub fn new<CS, CR>(
        config: Config,
        ctx: Context,
        vm: Vm,
        cot_send: (CS, CS, CS),
        cot_recv: CR,
    ) -> Self
    where
        CS: RCOTSender<Block> + Flush + Send + Sync + 'static,
        CR: RCOTReceiver<bool, Block> + Flush + Send + Sync + 'static,
    {
        let mut rng = rand::rng();

        let ke = Box::new(MpcKeyExchange::new(
            key_exchange::Role::Leader,
            ShareConversionSender::new(OLESender::new(
                Block::random(&mut rng),
                AnySender::new(RandomizeRCOTSender::new(cot_send.0)),
            )),
            ShareConversionReceiver::new(OLEReceiver::new(AnyReceiver::new(
                RandomizeRCOTReceiver::new(cot_recv),
            ))),
        )) as Box<dyn KeyExchange + Send + Sync>;

        let prf = Prf::new(PrfConfig::new(config.prf, MSMode::Standard));

        let encrypter = MpcAesGcm::new(
            ShareConversionSender::new(OLESender::new(
                Block::random(&mut rng),
                AnySender::new(RandomizeRCOTSender::new(cot_send.1)),
            )),
            Role::Leader,
        );
        let decrypter = MpcAesGcm::new(
            ShareConversionSender::new(OLESender::new(
                Block::random(&mut rng),
                AnySender::new(RandomizeRCOTSender::new(cot_send.2)),
            )),
            Role::Leader,
        );

        let record_layer = RecordLayer::new(Role::Leader, encrypter, decrypter);
        let session = MpcSession::new(ctx, vm, ke, prf, record_layer);
        let client_random = Random::new().expect("rng is available");

        let is_decrypting = !config.defer_decryption;
        Self {
            is_decrypting,
            state: State::Setup(Box::new(Setup {
                config,
                session,
                client_random,
            })),
        }
    }

    /// Allocates resources for the connection.
    pub fn alloc(&mut self) -> Result<SessionKeys, MpcTlsError> {
        let State::Setup(setup) = &mut self.state else {
            return Err(MpcTlsError::state("must be in setup state to allocate"));
        };

        setup.session.alloc(&setup.config)
    }

    /// Preprocesses the connection.
    #[instrument(level = "debug", skip_all, err)]
    pub async fn preprocess(&mut self) -> Result<(), MpcTlsError> {
        let State::Setup(setup) = self.state.take() else {
            return Err(MpcTlsError::state("must be in setup state to preprocess"));
        };
        let Setup {
            config,
            session,
            client_random,
        } = *setup;

        let mut session = session.preprocess().await?;

        session
            .ctx_mut()
            .io_mut()
            .send(MpcMessage::SetClientRandom(client_random.0))
            .await?;
        session.set_client_random(client_random.0);

        self.state = State::Setup(Box::new(Setup {
            config,
            session,
            client_random,
        }));

        Ok(())
    }

    /// Returns whether incoming application data is decrypted while the
    /// connection is active.
    pub fn is_decrypting(&self) -> bool {
        self.is_decrypting
    }

    /// Enables or disables decryption of incoming application data.
    pub fn enable_decryption(&mut self, enable: bool) {
        self.is_decrypting = enable;
        if let State::Live(live) = &mut self.state {
            live.is_decrypting = enable;
        }
    }

    /// Starts the TLS connection to `server_name`, emitting the ClientHello.
    pub async fn start(
        &mut self,
        client_config: Arc<ClientConfig>,
        server_name: ServerName,
    ) -> Result<(), Error> {
        let State::Setup(setup) = self.state.take() else {
            return Err(Error::General(
                "must be in setup state to start the connection".to_string(),
            ));
        };
        let Setup {
            session,
            client_random,
            ..
        } = *setup;

        let mut live = Live::new(
            session,
            client_config,
            server_name,
            client_random,
            self.is_decrypting,
        );
        let result = live.start().await;
        self.state = State::Live(Box::new(live));
        result
    }

    /// Processes any new packets buffered by [`MpcTlsLeader::read_tls`].
    pub async fn process_new_packets(&mut self) -> Result<IoState, Error> {
        self.live_mut()?.process_new_packets().await
    }

    /// Reads out buffered plaintext received from the peer.
    pub fn read_plaintext(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match &mut self.state {
            State::Live(live) => live.read_plaintext(buf),
            _ => Ok(0),
        }
    }

    /// Buffers plaintext to be encrypted and sent to the peer.
    pub fn write_plaintext(&mut self, buf: &[u8]) -> Result<usize, Error> {
        match &mut self.state {
            State::Live(live) => Ok(live.write_plaintext(buf)),
            _ => Ok(0),
        }
    }

    /// Reads TLS records from `rd` into the internal buffer.
    pub fn read_tls(&mut self, rd: &mut dyn io::Read) -> io::Result<usize> {
        match &mut self.state {
            State::Live(live) => live.read_tls(rd),
            _ => Ok(0),
        }
    }

    /// Writes buffered TLS records to `wr`.
    pub fn write_tls(&mut self, wr: &mut dyn io::Write) -> io::Result<usize> {
        match &mut self.state {
            State::Live(live) => live.write_tls(wr),
            _ => Ok(0),
        }
    }

    /// Returns whether the caller should read more TLS data.
    pub fn wants_read(&self) -> bool {
        matches!(&self.state, State::Live(live) if live.wants_read())
    }

    /// Returns whether the caller should write buffered TLS data.
    pub fn wants_write(&self) -> bool {
        matches!(&self.state, State::Live(live) if live.wants_write())
    }

    /// Returns whether there is no plaintext available to read immediately.
    pub fn plaintext_is_empty(&self) -> bool {
        match &self.state {
            State::Live(live) => live.plaintext_is_empty(),
            _ => true,
        }
    }

    /// Returns whether the sendable plaintext buffer is full.
    pub fn sendable_plaintext_is_full(&self) -> bool {
        match &self.state {
            State::Live(live) => live.sendable_plaintext_is_full(),
            _ => false,
        }
    }

    /// Returns whether the connection is currently performing the handshake.
    pub fn is_handshaking(&self) -> bool {
        match &self.state {
            State::Live(live) => live.is_handshaking(),
            _ => true,
        }
    }

    /// Returns whether the record layer has no buffered records.
    pub fn is_empty(&self) -> bool {
        match &self.state {
            State::Live(live) => live.is_empty(),
            _ => true,
        }
    }

    /// Queues a close_notify alert to be sent to the peer.
    pub async fn send_close_notify(&mut self) -> Result<(), Error> {
        self.live_mut()?.send_close_notify().await
    }

    /// Signals that the server has closed the connection, committing the
    /// transcript.
    pub async fn server_closed(&mut self) -> Result<(), Error> {
        self.live_mut()?.close_connection().await?;
        Ok(())
    }

    /// Returns the I/O context and transcript once the connection is closed and
    /// drained. Returns `None` if the connection is not closed yet.
    pub fn finish(&mut self) -> Option<(Context, TlsTranscript)> {
        match self.state.take() {
            State::Live(live) => match live.into_finished() {
                Ok((ctx, transcript)) => Some((ctx, transcript)),
                Err(live) => {
                    self.state = State::Live(live);
                    None
                }
            },
            other => {
                self.state = other;
                None
            }
        }
    }

    fn live_mut(&mut self) -> Result<&mut Live, Error> {
        match &mut self.state {
            State::Live(live) => Ok(live),
            _ => Err(Error::HandshakeNotComplete),
        }
    }
}

/// Values returned from [`MpcTlsLeader::process_new_packets`] describing the
/// current I/O state of the connection.
#[derive(Debug, PartialEq)]
pub struct IoState {
    tls_bytes_to_write: usize,
    plaintext_bytes_to_read: usize,
}

impl IoState {
    /// How many bytes could be written by [`MpcTlsLeader::write_tls`] right now.
    pub fn tls_bytes_to_write(&self) -> usize {
        self.tls_bytes_to_write
    }

    /// How many plaintext bytes could be read via
    /// [`MpcTlsLeader::read_plaintext`] without further I/O.
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

fn is_valid_ccs(msg: &OpaqueMessage) -> bool {
    // nb. this is prior to the record layer, so is unencrypted. see
    // third paragraph of section 5 in RFC8446.
    msg.typ == ContentType::ChangeCipherSpec && msg.payload.0 == [0x01]
}

/// The live TLS-over-MPC connection.
///
/// This fuses what upstream rustls splits across `ClientConnection` and
/// `CommonState` with the leader's MPC machinery: it owns the [`MpcSession`]
/// directly and drives the TLS protocol against it. The handshake state machine
/// ([`Handshake`]) operates on `&mut Live`, reaching both the framing state and
/// the MPC session through inherent methods.
pub(crate) struct Live {
    /// The MPC machinery shared with the follower.
    session: MpcSession,
    /// TLS client configuration.
    client_config: Arc<ClientConfig>,
    /// The server we are connecting to.
    server_name: ServerName,
    /// The client random, generated during setup.
    client_random: Random,
    /// The handshake state machine, or a latched fatal error.
    handshake: Result<Handshake, Error>,
    /// Whether incoming application data is decrypted while active.
    is_decrypting: bool,

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
    may_send_application_data: bool,
    may_receive_application_data: bool,
    aligned_handshake: bool,
    sent_fatal_alert: bool,
    has_received_close_notify: bool,
    received_middlebox_ccs: u8,

    message_fragmenter: MessageFragmenter,
    message_deframer: MessageDeframer,
    handshake_joiner: HandshakeJoiner,
    received_plaintext: ChunkVecBuffer,
    sendable_plaintext: ChunkVecBuffer,
    sendable_tls: ChunkVecBuffer,

    /// Server handshake parameters, collected during the handshake and used to
    /// build the transcript at close.
    server_params: Option<HandshakeData>,
    /// The handshake time, set when encryption is prepared.
    time: Option<u64>,
    /// The committed transcript, set once the connection is closed.
    transcript: Option<TlsTranscript>,
}

impl Live {
    fn new(
        session: MpcSession,
        client_config: Arc<ClientConfig>,
        server_name: ServerName,
        client_random: Random,
        is_decrypting: bool,
    ) -> Self {
        let max_fragment_size = client_config.max_fragment_size;
        Self {
            session,
            client_config,
            server_name,
            client_random,
            handshake: Ok(Handshake::Invalid),
            is_decrypting,
            negotiated_version: None,
            suite: None,
            alpn_protocol: None,
            encrypting: false,
            decrypting: false,
            may_send_application_data: false,
            may_receive_application_data: false,
            aligned_handshake: true,
            sent_fatal_alert: false,
            has_received_close_notify: false,
            received_middlebox_ccs: 0,
            message_fragmenter: MessageFragmenter::new(max_fragment_size)
                .expect("max_fragment_size was validated by ClientConfig"),
            message_deframer: MessageDeframer::new(),
            handshake_joiner: HandshakeJoiner::new(),
            received_plaintext: ChunkVecBuffer::new(Some(0)),
            sendable_plaintext: ChunkVecBuffer::new(Some(DEFAULT_BUFFER_LIMIT)),
            sendable_tls: ChunkVecBuffer::new(Some(DEFAULT_BUFFER_LIMIT)),
            server_params: None,
            time: None,
            transcript: None,
        }
    }

    /// Initiates the TLS protocol by emitting the ClientHello.
    async fn start(&mut self) -> Result<(), Error> {
        let config = self.client_config.clone();
        let server_name = self.server_name.clone();
        self.handshake = match hs::start_handshake(server_name, config, self).await {
            Ok(handshake) => Ok(handshake),
            Err(e) => return Err(e),
        };
        Ok(())
    }

    fn is_closed(&self) -> bool {
        self.transcript.is_some()
    }

    fn encryption_prepared(&self) -> bool {
        self.server_params.is_some()
    }

    // --- Consumer-facing I/O ---

    fn read_plaintext(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.received_plaintext.read(buf)
    }

    fn write_plaintext(&mut self, buf: &[u8]) -> usize {
        if buf.is_empty() {
            // Don't send empty fragments.
            return 0;
        }
        self.sendable_plaintext.append_limited_copy(buf)
    }

    fn read_tls(&mut self, rd: &mut dyn io::Read) -> io::Result<usize> {
        self.message_deframer.read(rd)
    }

    fn write_tls(&mut self, wr: &mut dyn io::Write) -> io::Result<usize> {
        self.sendable_tls.write_to(wr)
    }

    fn wants_read(&self) -> bool {
        // We want to read more data all the time, except when we have
        // unprocessed plaintext. This provides back-pressure to the TCP
        // buffers. We also don't want to read more after the peer has sent us a
        // close notification.
        self.received_plaintext.is_empty()
            && !self.has_received_close_notify
            && (self.may_send_application_data || self.sendable_tls.is_empty())
    }

    fn wants_write(&self) -> bool {
        !self.sendable_tls.is_empty()
    }

    fn plaintext_is_empty(&self) -> bool {
        self.received_plaintext.is_empty()
    }

    fn sendable_plaintext_is_full(&self) -> bool {
        self.sendable_plaintext.is_full()
    }

    fn is_handshaking(&self) -> bool {
        !(self.may_send_application_data && self.may_receive_application_data)
    }

    fn is_empty(&self) -> bool {
        self.session.record_layer_is_empty()
    }

    pub(crate) fn is_tls13(&self) -> bool {
        matches!(self.negotiated_version, Some(ProtocolVersion::TLSv1_3))
    }

    fn current_io_state(&self) -> IoState {
        IoState {
            tls_bytes_to_write: self.sendable_tls.len(),
            plaintext_bytes_to_read: self.received_plaintext.len(),
        }
    }

    // --- MPC session accessors used by the handshake ---

    pub(crate) fn client_random(&self) -> Random {
        self.client_random
    }

    pub(crate) fn client_key_share(&self) -> Result<PublicKey, MpcTlsError> {
        self.session.client_key_share()
    }

    /// Sends a protocol message to the follower.
    async fn send_message(&mut self, msg: MpcMessage) -> Result<(), MpcTlsError> {
        self.session.ctx_mut().io_mut().send(msg).await?;
        Ok(())
    }

    /// Computes the session keys from the handshake data collected by the
    /// client, preparing the record layer for encryption.
    #[instrument(level = "debug", skip_all, err)]
    pub(crate) async fn prepare_encryption(&mut self, hs: HandshakeData) -> Result<(), MpcTlsError> {
        debug!("preparing encryption");

        if hs.server_key.group != tls_core::msgs::enums::NamedGroup::secp256r1 {
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

    // --- Record layer plumbing ---

    async fn push_incoming(&mut self, msg: OpaqueMessage) -> Result<(), MpcTlsError> {
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
        .await
    }

    fn next_incoming(&mut self) -> Option<PlainMessage> {
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

    #[instrument(level = "debug", skip_all, err)]
    async fn push_outgoing(&mut self, msg: PlainMessage) -> Result<(), MpcTlsError> {
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
        .await
    }

    fn next_outgoing(&mut self) -> Option<OpaqueMessage> {
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

    /// Flushes the record layer if there is buffered work and the connection is
    /// in a state where flushing is meaningful.
    #[instrument(level = "debug", skip_all, err)]
    async fn flush_records(&mut self) -> Result<(), Error> {
        if !self.encryption_prepared() {
            debug!("handshake is not complete, skipping flush");
            return Ok(());
        }
        // The record layer is guaranteed to be empty after the connection was
        // closed.
        if self.is_closed() {
            return Ok(());
        }
        if !self.session.wants_flush() {
            debug!("record layer is empty, skipping flush");
            return Ok(());
        }

        debug!("flushing record layer");
        let is_decrypting = self.is_decrypting;
        self.send_message(MpcMessage::Flush { is_decrypting }).await?;
        self.session.flush(is_decrypting).await?;

        Ok(())
    }

    // --- Connection driving ---

    /// Processes any new packets read by a previous call to
    /// [`Live::read_tls`].
    pub(crate) async fn process_new_packets(&mut self) -> Result<IoState, Error> {
        let mut handshake = match mem::replace(&mut self.handshake, Err(Error::HandshakeNotComplete))
        {
            Ok(handshake) => handshake,
            Err(e) => {
                self.handshake = Err(e.clone());
                return Err(e);
            }
        };

        if self.message_deframer.desynced {
            return Err(Error::CorruptMessage);
        }

        // Process outgoing plaintext buffer and encrypt messages.
        self.flush_plaintext().await?;

        // Process new messages.
        while let Some(msg) = self.message_deframer.frames.pop_front() {
            if let Some(plain) = self.process_incoming_opaque(msg).await? {
                match self.process_incoming_plain(plain, handshake).await {
                    Ok(new) => handshake = new,
                    Err(e) => {
                        self.handshake = Err(e.clone());
                        return Err(e);
                    }
                }
            }
        }

        self.flush_records().await?;

        // Process pending decrypted messages.
        while let Some(msg) = self.next_incoming() {
            match self.process_incoming_plain(msg, handshake).await {
                Ok(new) => handshake = new,
                Err(e) => {
                    self.handshake = Err(e.clone());
                    return Err(e);
                }
            }
        }

        while let Some(msg) = self.next_outgoing() {
            self.queue_tls_message(msg);
        }

        self.handshake = Ok(handshake);

        Ok(self.current_io_state())
    }

    async fn process_incoming_opaque(
        &mut self,
        msg: OpaqueMessage,
    ) -> Result<Option<PlainMessage>, Error> {
        // Drop CCS messages during handshake in TLS1.3.
        if msg.typ == ContentType::ChangeCipherSpec
            && !self.may_receive_application_data
            && self.is_tls13()
        {
            if !is_valid_ccs(&msg) || self.received_middlebox_ccs > TLS13_MAX_DROPPED_CCS {
                self.send_fatal_alert(AlertDescription::UnexpectedMessage)
                    .await?;
                return Err(Error::PeerMisbehavedError(
                    "illegal middlebox CCS received".into(),
                ));
            } else {
                self.received_middlebox_ccs += 1;
                trace!("Dropping CCS");
                return Ok(None);
            }
        }

        if self.decrypting {
            self.push_incoming(msg).await?;
            Ok(None)
        } else {
            Ok(Some(msg.into_plain_message()))
        }
    }

    async fn process_incoming_plain(
        &mut self,
        msg: PlainMessage,
        handshake: Handshake,
    ) -> Result<Handshake, Error> {
        // For handshake messages, we need to join them before parsing and
        // processing.
        if self.handshake_joiner.want_message(&msg) {
            match self.handshake_joiner.take_message(msg) {
                Some(_) => {}
                None => {
                    self.send_fatal_alert(AlertDescription::DecodeError).await?;
                    return Err(Error::CorruptMessagePayload(ContentType::Handshake));
                }
            }
            return self.process_new_handshake_messages(handshake).await;
        }

        let msg = Message::try_from(msg)?;

        if let MessagePayload::Alert(alert) = &msg.payload {
            self.process_alert(alert).await?;
            return Ok(handshake);
        }

        self.process_main_protocol(msg, handshake).await
    }

    async fn process_new_handshake_messages(
        &mut self,
        mut handshake: Handshake,
    ) -> Result<Handshake, Error> {
        self.aligned_handshake = self.handshake_joiner.is_empty();
        while let Some(msg) = self.handshake_joiner.frames.pop_front() {
            handshake = self.process_main_protocol(msg, handshake).await?;
        }
        Ok(handshake)
    }

    async fn process_main_protocol(
        &mut self,
        msg: Message,
        handshake: Handshake,
    ) -> Result<Handshake, Error> {
        // For TLS1.2, outside of the handshake, send rejection alerts for
        // renegotiation requests. These can occur any time.
        if self.may_receive_application_data
            && !self.is_tls13()
            && msg.is_handshake_type(HandshakeType::HelloRequest)
        {
            self.send_warning_alert(AlertDescription::NoRenegotiation)
                .await?;
            return Ok(handshake);
        }

        match handshake.handle(self, msg).await {
            Ok(next) => Ok(next),
            Err(e @ Error::InappropriateMessage { .. })
            | Err(e @ Error::InappropriateHandshakeMessage { .. }) => {
                self.send_fatal_alert(AlertDescription::UnexpectedMessage)
                    .await?;
                Err(e)
            }
            Err(e) => Err(e),
        }
    }

    // --- Framing / alerts (formerly CommonState) ---

    pub(crate) async fn check_aligned_handshake(&mut self) -> Result<(), Error> {
        if !self.aligned_handshake {
            self.send_fatal_alert(AlertDescription::UnexpectedMessage)
                .await?;
            Err(Error::PeerMisbehavedError(
                "key epoch or handshake flight with pending fragment".to_string(),
            ))
        } else {
            Ok(())
        }
    }

    pub(crate) async fn illegal_param(&mut self, why: &str) -> Result<Error, Error> {
        self.send_fatal_alert(AlertDescription::IllegalParameter)
            .await?;
        Ok(Error::PeerMisbehavedError(why.to_string()))
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

    /// Fragments `m`, encrypts the fragments, and queues them for sending.
    ///
    /// Unlike upstream rustls there is no sequence-space exhaustion guard: the
    /// MPC record layer enforces the configured traffic limits, which bound the
    /// number of records far below the sequence space.
    async fn send_msg_encrypt(&mut self, m: PlainMessage) -> Result<(), Error> {
        let mut plain_messages = VecDeque::new();
        self.message_fragmenter.fragment(m, &mut plain_messages);

        for m in plain_messages {
            self.send_single_fragment(m).await?;
        }
        Ok(())
    }

    async fn send_appdata_encrypt(&mut self, payload: &[u8]) -> Result<usize, Error> {
        let mut plain_messages = VecDeque::new();
        self.message_fragmenter.fragment(
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
        debug_assert!(self.encrypting);
        self.push_outgoing(m).await?;
        Ok(())
    }

    pub(crate) async fn start_outgoing_traffic(&mut self) -> Result<(), Error> {
        self.may_send_application_data = true;
        self.flush_plaintext().await
    }

    pub(crate) async fn start_traffic(&mut self) -> Result<(), Error> {
        self.may_receive_application_data = true;
        self.session.start_traffic();
        self.send_message(MpcMessage::StartTraffic).await?;
        self.start_outgoing_traffic().await
    }

    /// Sends and encrypts any buffered plaintext. Does nothing during the
    /// handshake.
    pub(crate) async fn flush_plaintext(&mut self) -> Result<(), Error> {
        if !self.may_send_application_data {
            return Ok(());
        }

        while let Some(buf) = self.sendable_plaintext.pop() {
            self.send_appdata_encrypt(&buf).await?;
        }

        Ok(())
    }

    fn queue_tls_message(&mut self, m: OpaqueMessage) {
        self.sendable_tls.append(m.encode());
    }

    pub(crate) async fn send_msg(&mut self, m: Message, must_encrypt: bool) -> Result<(), Error> {
        if !must_encrypt {
            let mut to_send = VecDeque::new();
            self.message_fragmenter.fragment(m.into(), &mut to_send);
            for mm in to_send {
                self.queue_tls_message(mm.into_unencrypted_opaque());
            }
            Ok(())
        } else {
            self.send_msg_encrypt(m.into()).await
        }
    }

    pub(crate) fn take_received_plaintext(&mut self, bytes: Payload) {
        self.received_plaintext.append(bytes.0);
    }

    async fn send_warning_alert(&mut self, desc: AlertDescription) -> Result<(), Error> {
        warn!("Sending warning alert {:?}", desc);
        self.send_warning_alert_no_log(desc).await
    }

    async fn process_alert(&mut self, alert: &AlertMessagePayload) -> Result<(), Error> {
        if let AlertLevel::Unknown(_) = alert.level {
            self.send_fatal_alert(AlertDescription::IllegalParameter)
                .await?;
        }

        if alert.description == AlertDescription::CloseNotify {
            self.has_received_close_notify = true;
            return Ok(());
        }

        if alert.level == AlertLevel::Warning {
            if self.is_tls13() && alert.description != AlertDescription::UserCanceled {
                self.send_fatal_alert(AlertDescription::DecodeError).await?;
            } else {
                warn!("TLS alert warning received: {:#?}", alert);
                return Ok(());
            }
        }

        error!("TLS alert received: {:#?}", alert);
        Err(Error::AlertReceived(alert.description))
    }

    pub(crate) async fn send_fatal_alert(&mut self, desc: AlertDescription) -> Result<(), Error> {
        warn!("Sending fatal alert {:?}", desc);
        debug_assert!(!self.sent_fatal_alert);
        let m = Message::build_alert(AlertLevel::Fatal, desc);
        let must_encrypt = self.encrypting;
        self.send_msg(m, must_encrypt).await?;
        self.sent_fatal_alert = true;
        Ok(())
    }

    /// Queues a close_notify warning alert to be sent in the next
    /// [`Live::write_tls`] call.
    async fn send_close_notify(&mut self) -> Result<(), Error> {
        debug!("Sending warning alert {:?}", AlertDescription::CloseNotify);
        self.send_warning_alert_no_log(AlertDescription::CloseNotify)
            .await
    }

    async fn send_warning_alert_no_log(&mut self, desc: AlertDescription) -> Result<(), Error> {
        let m = Message::build_alert(AlertLevel::Warning, desc);
        let must_encrypt = self.encrypting;
        self.send_msg(m, must_encrypt).await
    }

    // --- Connection closure ---

    /// Closes the connection, committing the transcript. The connection remains
    /// in place afterwards so buffered plaintext can be drained.
    #[instrument(name = "close_connection", level = "debug", skip_all, err)]
    async fn close_connection(&mut self) -> Result<(), MpcTlsError> {
        if self.is_closed() {
            return Ok(());
        }

        debug!("closing connection");
        self.send_message(MpcMessage::CloseConnection).await?;

        debug!("committing to transcript");
        let (sent_records, recv_records) = self.session.commit().await?;
        debug!("committed to transcript");

        let hs = self
            .server_params
            .as_ref()
            .ok_or_else(|| MpcTlsError::state("server parameters not set"))?;
        let time = self
            .time
            .ok_or_else(|| MpcTlsError::state("handshake time not set"))?;

        let server_cert_chain = hs
            .server_cert_details
            .cert_chain()
            .iter()
            .map(|cert| CertificateDer(cert.0.clone()))
            .collect();

        let mut sig_msg = Vec::new();
        sig_msg.extend_from_slice(&self.client_random.0);
        sig_msg.extend_from_slice(&hs.server_random.0);
        sig_msg.extend_from_slice(hs.server_kx_details.kx_params());

        let server_signature_alg = verify_sig_determine_alg(
            &hs.server_cert_details.cert_chain()[0],
            &sig_msg,
            hs.server_kx_details.kx_sig(),
        )
        .expect("only supported signature should have been accepted");

        let server_signature = ServerSignature {
            alg: server_signature_alg.into(),
            sig: hs.server_kx_details.kx_sig().sig.0.clone(),
        };

        let binding = CertBinding::V1_2(CertBindingV1_2 {
            client_random: self.client_random.0,
            server_random: hs.server_random.0,
            server_ephemeral_key: hs
                .server_key
                .clone()
                .try_into()
                .expect("only supported key scheme should have been accepted"),
        });

        let transcript = TlsTranscript::builder()
            .time(time)
            .version(TlsVersion::V1_2)
            .server_signature(server_signature)
            .server_cert_chain(server_cert_chain)
            .certificate_binding(binding)
            .records_sent(sent_records)
            .records_recv(recv_records)
            .build()
            .map_err(MpcTlsError::other)?;

        self.session.verify_transcript(&transcript)?;

        self.transcript = Some(transcript);

        Ok(())
    }

    /// Consumes the connection once it is closed, returning the I/O context and
    /// transcript. Returns the connection unchanged if it is not closed yet.
    fn into_finished(mut self: Box<Self>) -> Result<(Context, TlsTranscript), Box<Self>> {
        match self.transcript.take() {
            Some(transcript) => {
                let (ctx, _record_layer) = self.session.into_closed();
                Ok((ctx, transcript))
            }
            None => Err(self),
        }
    }
}
