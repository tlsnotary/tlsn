//! MPC-TLS leader.
//!
//! The leader is the unified TLS client. Unlike upstream rustls it performs no
//! cryptographic operations itself: the key exchange, the PRF and record
//! encryption/decryption are delegated to an [`MpcSession`], which executes
//! them jointly with the follower using MPC. This module drives the TLS
//! protocol — message framing, the handshake flow, alerts and connection
//! closure — directly against that session, with no intermediate "backend"
//! abstraction.
//!
//! [`MpcTlsLeader`] is the single public type. Its lifecycle is the private
//! [`State`] enum:
//!
//! * [`State::Setup`] — MPC resources are allocated and preprocessed before the
//!   handshake begins.
//! * [`State::Live`] — the connection is driven. A [`Live`] owns the connection
//!   I/O and MPC session ([`Conn`]) plus a [`Phase`] that is either
//!   [`Phase::Handshaking`] (the handshake state machine and its inputs) or
//!   [`Phase::Online`] (application-data transfer). The phase flips in place
//!   when the handshake completes, so a single `process_new_packets` call can
//!   finish the handshake and process the first application records that
//!   follow. The `Live` remains in place after the connection closes so
//!   buffered plaintext can be drained before [`MpcTlsLeader::finish`].

use std::{io, mem, sync::Arc};

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
    msgs::{
        enums::{AlertDescription, ContentType},
        handshake::Random,
        message::{Message, MessagePayload, OpaqueMessage, PlainMessage},
    },
    verify::verify_sig_determine_alg,
};
use tlsn_core::{
    connection::{CertBinding, CertBindingV1_2, ServerSignature, TlsVersion},
    transcript::TlsTranscript,
    webpki::CertificateDer,
};
use tracing::{debug, instrument, trace};

use crate::{
    Config, MpcTlsError, Role, SessionKeys, Vm,
    conn::{Conn, IoState, TLS13_MAX_DROPPED_CCS, TlsIo, is_valid_ccs},
    handshake::{
        ClientConfig, ServerName,
        error::Error,
        hs::{self, Handshake},
        traffic,
    },
    msg::Message as MpcMessage,
    record_layer::{RecordLayer, aead::MpcAesGcm},
    session::MpcSession,
};

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
        // Build the framing first: this validates the configured fragment size,
        // so a bad configuration is reported without tearing down the session.
        let io = TlsIo::new(client_config.max_fragment_size)?;

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

        let conn = Conn::new(io, session, client_random);
        let mut live = Live::new(conn, client_config, server_name, self.is_decrypting);
        let result = live.start_handshake().await;
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
            State::Live(live) => live.conn.io.read_plaintext(buf),
            _ => Ok(0),
        }
    }

    /// Buffers plaintext to be encrypted and sent to the peer.
    pub fn write_plaintext(&mut self, buf: &[u8]) -> Result<usize, Error> {
        match &mut self.state {
            State::Live(live) => Ok(live.conn.io.write_plaintext(buf)),
            _ => Ok(0),
        }
    }

    /// Reads TLS records from `rd` into the internal buffer.
    pub fn read_tls(&mut self, rd: &mut dyn io::Read) -> io::Result<usize> {
        match &mut self.state {
            State::Live(live) => live.conn.io.read_tls(rd),
            _ => Ok(0),
        }
    }

    /// Writes buffered TLS records to `wr`.
    pub fn write_tls(&mut self, wr: &mut dyn io::Write) -> io::Result<usize> {
        match &mut self.state {
            State::Live(live) => live.conn.io.write_tls(wr),
            _ => Ok(0),
        }
    }

    /// Returns whether the caller should read more TLS data.
    pub fn wants_read(&self) -> bool {
        matches!(&self.state, State::Live(live) if live.wants_read())
    }

    /// Returns whether the caller should write buffered TLS data.
    pub fn wants_write(&self) -> bool {
        matches!(&self.state, State::Live(live) if live.conn.io.wants_write())
    }

    /// Returns whether there is no plaintext available to read immediately.
    pub fn plaintext_is_empty(&self) -> bool {
        match &self.state {
            State::Live(live) => live.conn.io.plaintext_is_empty(),
            _ => true,
        }
    }

    /// Returns whether the sendable plaintext buffer is full.
    pub fn sendable_plaintext_is_full(&self) -> bool {
        match &self.state {
            State::Live(live) => live.conn.io.sendable_plaintext_is_full(),
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
            State::Live(live) => live.conn.session.record_layer_is_empty(),
            _ => true,
        }
    }

    /// Queues a close_notify alert to be sent to the peer.
    pub async fn send_close_notify(&mut self) -> Result<(), Error> {
        self.live_mut()?.conn.send_close_notify().await
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

/// The live TLS-over-MPC connection.
///
/// A thin lifecycle/phase driver over [`Conn`]: it pumps records through the
/// connection and dispatches them to the current [`Phase`]. The handshake state
/// machine and the online router operate directly on `&mut Conn`, not on
/// `Live`, so there is no forwarding layer here.
pub(crate) struct Live {
    conn: Conn,
    phase: Phase,
    /// Whether incoming application data is decrypted while active.
    is_decrypting: bool,
    /// The committed transcript, set once the connection is closed.
    transcript: Option<TlsTranscript>,
}

/// Which phase of the connection is active.
enum Phase {
    /// The handshake is in progress; holds the handshake state machine and its
    /// inputs.
    Handshaking(Box<Handshaking>),
    /// The handshake is complete; application data flows. No handshake state is
    /// retained.
    Online,
}

/// Handshake-phase-only state.
struct Handshaking {
    /// The handshake state machine, or a latched fatal error.
    handshake: Result<Handshake, Error>,
    client_config: Arc<ClientConfig>,
    server_name: ServerName,
}

impl Live {
    fn new(
        conn: Conn,
        client_config: Arc<ClientConfig>,
        server_name: ServerName,
        is_decrypting: bool,
    ) -> Self {
        Self {
            conn,
            phase: Phase::Handshaking(Box::new(Handshaking {
                // The handshake state is installed by `start_handshake`; until
                // then any attempt to drive the connection reports
                // `HandshakeNotComplete`.
                handshake: Err(Error::HandshakeNotComplete),
                client_config,
                server_name,
            })),
            is_decrypting,
            transcript: None,
        }
    }

    /// Initiates the TLS protocol by emitting the ClientHello.
    ///
    /// On failure the error is latched into the handshake state so subsequent
    /// `process_new_packets` calls surface it rather than driving a
    /// half-started connection.
    async fn start_handshake(&mut self) -> Result<(), Error> {
        let (config, server_name) = match &self.phase {
            Phase::Handshaking(hs) => (hs.client_config.clone(), hs.server_name.clone()),
            Phase::Online => {
                return Err(Error::General("connection already started".to_string()));
            }
        };

        let result = hs::start_handshake(server_name, config, &mut self.conn).await;

        match &mut self.phase {
            Phase::Handshaking(hs) => match result {
                Ok(handshake) => {
                    hs.handshake = Ok(handshake);
                    Ok(())
                }
                Err(e) => {
                    hs.handshake = Err(e.clone());
                    Err(e)
                }
            },
            Phase::Online => Err(Error::General("connection already started".to_string())),
        }
    }

    fn is_handshaking(&self) -> bool {
        matches!(self.phase, Phase::Handshaking(_))
    }

    fn is_online(&self) -> bool {
        matches!(self.phase, Phase::Online)
    }

    fn is_closed(&self) -> bool {
        self.transcript.is_some()
    }

    fn wants_read(&self) -> bool {
        // We want to read more data all the time, except when we have
        // unprocessed plaintext (back-pressure) or the peer has sent a
        // close_notify. During the handshake we also don't read while we still
        // have TLS data queued to send.
        self.conn.io.plaintext_is_empty()
            && !self.conn.io.has_received_close_notify()
            && (self.is_online() || self.conn.io.sendable_tls_is_empty())
    }

    /// Signals that the handshake is complete: starts application traffic and
    /// transitions to the online phase.
    async fn enter_online(&mut self) -> Result<(), Error> {
        self.conn.start_traffic().await?;
        self.phase = Phase::Online;
        // Now that we may send application data, flush any plaintext that was
        // buffered while the handshake was in progress.
        self.flush_plaintext().await
    }

    /// Sends and encrypts any buffered plaintext. Does nothing during the
    /// handshake.
    async fn flush_plaintext(&mut self) -> Result<(), Error> {
        if !self.is_online() {
            return Ok(());
        }
        while let Some(buf) = self.conn.io.next_sendable_plaintext() {
            self.conn.send_appdata_encrypt(&buf).await?;
        }
        Ok(())
    }

    /// Flushes the record layer if the connection is in a state where flushing
    /// is meaningful.
    async fn flush_records(&mut self) -> Result<(), Error> {
        if !self.conn.encryption_prepared() {
            debug!("handshake is not complete, skipping flush");
            return Ok(());
        }
        // The record layer is guaranteed to be empty after the connection was
        // closed.
        if self.is_closed() {
            return Ok(());
        }
        self.conn.flush_records(self.is_decrypting).await
    }

    // --- Connection driving ---

    /// Processes any new packets read by a previous call to `read_tls`.
    pub(crate) async fn process_new_packets(&mut self) -> Result<IoState, Error> {
        if let Phase::Handshaking(hs) = &self.phase
            && let Err(e) = &hs.handshake
        {
            return Err(e.clone());
        }

        if self.conn.io.deframer_desynced() {
            return Err(Error::CorruptMessage);
        }

        // Process outgoing plaintext buffer and encrypt messages.
        self.flush_plaintext().await?;

        // Process newly deframed records.
        while let Some(msg) = self.conn.io.next_received_frame() {
            let plain = match self.process_incoming_opaque(msg).await {
                Ok(plain) => plain,
                Err(e) => return Err(self.latch(e)),
            };
            if let Some(plain) = plain
                && let Err(e) = self.process_incoming_plain(plain).await
            {
                return Err(self.latch(e));
            }
        }

        self.flush_records().await?;

        // Process pending decrypted messages.
        while let Some(msg) = self.conn.next_incoming() {
            if let Err(e) = self.process_incoming_plain(msg).await {
                return Err(self.latch(e));
            }
        }

        while let Some(msg) = self.conn.next_outgoing() {
            self.conn.io.queue_tls_message(msg);
        }

        Ok(self.conn.io.current_io_state())
    }

    /// Latches a fatal error into the handshake state (so it is returned by
    /// future calls) and returns it.
    fn latch(&mut self, e: Error) -> Error {
        if let Phase::Handshaking(hs) = &mut self.phase {
            hs.handshake = Err(e.clone());
        }
        e
    }

    async fn process_incoming_opaque(
        &mut self,
        msg: OpaqueMessage,
    ) -> Result<Option<PlainMessage>, Error> {
        // Drop CCS messages during the TLS1.3 handshake.
        if msg.typ == ContentType::ChangeCipherSpec
            && self.is_handshaking()
            && self.conn.io.is_tls13()
        {
            if !is_valid_ccs(&msg) || self.conn.io.received_middlebox_ccs() > TLS13_MAX_DROPPED_CCS
            {
                self.conn
                    .send_fatal_alert(AlertDescription::UnexpectedMessage)
                    .await?;
                return Err(Error::PeerMisbehavedError(
                    "illegal middlebox CCS received".into(),
                ));
            } else {
                self.conn.io.inc_received_middlebox_ccs();
                trace!("Dropping CCS");
                return Ok(None);
            }
        }

        if self.conn.io.decrypting() {
            self.conn.push_incoming(msg).await?;
            Ok(None)
        } else {
            Ok(Some(msg.into_plain_message()))
        }
    }

    async fn process_incoming_plain(&mut self, msg: PlainMessage) -> Result<(), Error> {
        // Handshake messages must be reassembled before processing.
        if self.conn.io.joiner_wants(&msg) {
            if self.conn.io.join(msg).is_none() {
                self.conn
                    .send_fatal_alert(AlertDescription::DecodeError)
                    .await?;
                return Err(Error::CorruptMessagePayload(ContentType::Handshake));
            }
            self.conn.io.mark_aligned_handshake();
            while let Some(msg) = self.conn.io.next_joined_message() {
                self.process_message(msg).await?;
            }
            return Ok(());
        }

        let msg = Message::try_from(msg)?;

        if let MessagePayload::Alert(alert) = &msg.payload {
            self.conn.process_alert(alert).await?;
            return Ok(());
        }

        self.process_message(msg).await
    }

    /// Dispatches a fully-parsed TLS message according to the current phase.
    async fn process_message(&mut self, msg: Message) -> Result<(), Error> {
        match &self.phase {
            Phase::Handshaking(_) => self.step_handshake(msg).await,
            Phase::Online => traffic::process_online(&mut self.conn, msg).await,
        }
    }

    /// Steps the handshake state machine with `msg`, transitioning to the
    /// online phase if the handshake completes.
    async fn step_handshake(&mut self, msg: Message) -> Result<(), Error> {
        let handshake = match &mut self.phase {
            Phase::Handshaking(hs) => {
                match mem::replace(&mut hs.handshake, Err(Error::HandshakeNotComplete)) {
                    Ok(handshake) => handshake,
                    Err(e) => return Err(e),
                }
            }
            Phase::Online => return Err(Error::General("not in handshaking phase".to_string())),
        };

        let next = match handshake.handle(&mut self.conn, msg).await {
            Ok(next) => next,
            Err(e @ Error::InappropriateMessage { .. })
            | Err(e @ Error::InappropriateHandshakeMessage { .. }) => {
                self.conn
                    .send_fatal_alert(AlertDescription::UnexpectedMessage)
                    .await?;
                return Err(e);
            }
            Err(e) => return Err(e),
        };

        if matches!(next, Handshake::Complete) {
            self.enter_online().await
        } else {
            if let Phase::Handshaking(hs) = &mut self.phase {
                hs.handshake = Ok(next);
            }
            Ok(())
        }
    }

    // --- Connection closure ---

    /// Closes the connection, committing the transcript. The connection remains
    /// in place afterwards so buffered plaintext can be drained.
    #[instrument(name = "close_connection", level = "debug", skip_all, err)]
    async fn close_connection(&mut self) -> Result<(), MpcTlsError> {
        if self.is_closed() {
            return Ok(());
        }
        if !self.conn.encryption_prepared() {
            return Err(MpcTlsError::state(
                "cannot close connection before encryption is prepared",
            ));
        }

        debug!("closing connection");
        self.conn.send_message(MpcMessage::CloseConnection).await?;

        debug!("committing to transcript");
        let (sent_records, recv_records) = self.conn.session.commit().await?;
        debug!("committed to transcript");

        let hs = self
            .conn
            .server_params
            .as_ref()
            .ok_or_else(|| MpcTlsError::state("server parameters not set"))?;
        let time = self
            .conn
            .time
            .ok_or_else(|| MpcTlsError::state("handshake time not set"))?;

        let server_cert_chain = hs
            .server_cert_details
            .cert_chain()
            .iter()
            .map(|cert| CertificateDer(cert.0.clone()))
            .collect();

        let mut sig_msg = Vec::new();
        sig_msg.extend_from_slice(&self.conn.client_random.0);
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
            client_random: self.conn.client_random.0,
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

        self.conn.session.verify_transcript(&transcript)?;

        self.transcript = Some(transcript);

        Ok(())
    }

    /// Consumes the connection once it is closed, returning the I/O context and
    /// transcript. Returns the connection unchanged if it is not closed yet.
    fn into_finished(mut self: Box<Self>) -> Result<(Context, TlsTranscript), Box<Self>> {
        match self.transcript.take() {
            Some(transcript) => {
                let (ctx, _record_layer) = self.conn.session.into_closed();
                Ok((ctx, transcript))
            }
            None => Err(self),
        }
    }
}
