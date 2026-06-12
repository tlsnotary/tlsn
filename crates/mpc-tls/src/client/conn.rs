use tracing::{debug, error, trace, warn};
use crate::{
    MpcTlsLeader,
    client::{error::Error, vecbuf::ChunkVecBuffer},
};
use async_trait::async_trait;
use std::{
    collections::VecDeque,
    convert::TryFrom,
    fmt, io, mem,
    ops::{Deref, DerefMut},
};
use tls_core::{
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
};

/// Values of this structure are returned from
/// [`ClientConnection::process_new_packets`] and tell the caller the current I/O
/// state of the TLS connection.
#[derive(Debug, PartialEq)]
pub struct IoState {
    tls_bytes_to_write: usize,
    plaintext_bytes_to_read: usize,
}

impl IoState {
    /// How many bytes could be written by [`CommonState::write_tls`] if called
    /// right now.  A non-zero value implies [`CommonState::wants_write`].
    pub fn tls_bytes_to_write(&self) -> usize {
        self.tls_bytes_to_write
    }

    /// How many plaintext bytes could be obtained via
    /// [`ClientConnection::read_plaintext`] without further I/O.
    pub fn plaintext_bytes_to_read(&self) -> usize {
        self.plaintext_bytes_to_read
    }
}

/// How many ChangeCipherSpec messages we accept and drop in TLS1.3 handshakes.
/// The spec says 1, but implementations (namely the boringssl test suite) get
/// this wrong.  BoringSSL itself accepts up to 32.
static TLS13_MAX_DROPPED_CCS: u8 = 2u8;

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

fn is_valid_ccs(msg: &OpaqueMessage) -> bool {
    // nb. this is prior to the record layer, so is unencrypted. see
    // third paragraph of section 5 in RFC8446.
    msg.typ == ContentType::ChangeCipherSpec && msg.payload.0 == [0x01]
}

/// This represents a single TLS client connection.
pub struct ClientConnection {
    state: Result<Box<dyn State>, Error>,
    common_state: CommonState,
    message_deframer: MessageDeframer,
    handshake_joiner: HandshakeJoiner,
}

impl fmt::Debug for ClientConnection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ClientConnection").finish()
    }
}

impl ClientConnection {
    pub(crate) fn new_inner(state: Box<dyn State>, common_state: CommonState) -> Self {
        Self {
            state: Ok(state),
            common_state,
            message_deframer: MessageDeframer::new(),
            handshake_joiner: HandshakeJoiner::new(),
        }
    }

    /// Reads out any buffered plaintext received from the peer. Returns the
    /// number of bytes read.
    pub fn read_plaintext(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.common_state.received_plaintext.read(buf)
    }

    /// Returns whether the MPC record layer has no buffered records.
    pub fn is_empty(&self) -> bool {
        self.common_state.backend.is_empty()
    }

    /// Initiate the TLS protocol
    pub async fn start(&mut self) -> Result<(), Error> {
        let state = match mem::replace(&mut self.state, Err(Error::HandshakeNotComplete)) {
            Ok(state) => state,
            Err(e) => {
                self.state = Err(e.clone());
                return Err(e);
            }
        };
        self.state = state.start(&mut self.common_state).await;
        Ok(())
    }

    /// Signals that the server has closed the connection.
    pub async fn server_closed(&mut self) -> Result<(), Error> {
        self.common_state.backend.close_connection().await?;
        Ok(())
    }

    async fn process_incoming_opaque(
        &mut self,
        msg: OpaqueMessage,
    ) -> Result<Option<PlainMessage>, Error> {
        // Drop CCS messages during handshake in TLS1.3
        if msg.typ == ContentType::ChangeCipherSpec
            && !self.common_state.may_receive_application_data
            && self.common_state.is_tls13()
        {
            if !is_valid_ccs(&msg)
                || self.common_state.received_middlebox_ccs > TLS13_MAX_DROPPED_CCS
            {
                // "An implementation which receives any other change_cipher_spec value or
                //  which receives a protected change_cipher_spec record MUST abort the
                //  handshake with an "unexpected_message" alert."
                self.common_state
                    .send_fatal_alert(AlertDescription::UnexpectedMessage)
                    .await?;
                return Err(Error::PeerMisbehavedError(
                    "illegal middlebox CCS received".into(),
                ));
            } else {
                self.common_state.received_middlebox_ccs += 1;
                trace!("Dropping CCS");
                return Ok(None);
            }
        }

        // Decrypt if demanded by current state.
        if self.common_state.decrypting {
            self.common_state.decrypt_incoming(msg).await?;

            Ok(None)
        } else {
            Ok(Some(msg.into_plain_message()))
        }
    }

    async fn process_incoming_plain(
        &mut self,
        msg: PlainMessage,
        state: Box<dyn State>,
    ) -> Result<Box<dyn State>, Error> {
        // For handshake messages, we need to join them before parsing
        // and processing.
        if self.handshake_joiner.want_message(&msg) {
            match self.handshake_joiner.take_message(msg) {
                Some(_) => {}
                None => {
                    self.common_state
                        .send_fatal_alert(AlertDescription::DecodeError)
                        .await?;
                    return Err(Error::CorruptMessagePayload(ContentType::Handshake));
                }
            }
            return self.process_new_handshake_messages(state).await;
        }

        // Now we can fully parse the message payload.
        let msg = Message::try_from(msg)?;

        // For alerts, we have separate logic.
        if let MessagePayload::Alert(alert) = &msg.payload {
            self.common_state.process_alert(alert).await?;
            return Ok(state);
        }

        self.common_state.process_main_protocol(msg, state).await
    }

    /// Processes any new packets read by a previous call to
    /// [`ClientConnection::read_tls`].
    ///
    /// Errors from this function relate to TLS protocol errors, and
    /// are fatal to the connection.  Future calls after an error will do
    /// no new work and will return the same error. After an error is
    /// received from [`process_new_packets`], you should not call [`read_tls`]
    /// any more (it will fill up buffers to no purpose). However, you
    /// may call the other methods on the connection, including `write`,
    /// `send_close_notify`, and `write_tls`. Most likely you will want to
    /// call `write_tls` to send any alerts queued by the error and then
    /// close the underlying connection.
    ///
    /// Success from this function comes with some sundry state data
    /// about the connection.
    ///
    /// [`read_tls`]: ClientConnection::read_tls
    /// [`process_new_packets`]: ClientConnection::process_new_packets
    pub async fn process_new_packets(&mut self) -> Result<IoState, Error> {
        let mut state = match mem::replace(&mut self.state, Err(Error::HandshakeNotComplete)) {
            Ok(state) => state,
            Err(e) => {
                self.state = Err(e.clone());
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
            // If we're not decrypting yet, we process it immediately. Otherwise it will be
            // pushed to the backend.
            if let Some(plain) = self.process_incoming_opaque(msg).await? {
                match self.process_incoming_plain(plain, state).await {
                    Ok(new) => state = new,
                    Err(e) => {
                        self.state = Err(e.clone());
                        return Err(e);
                    }
                }
            }
        }
        self.backend.flush().await?;

        // Process pending decrypted messages.
        while let Some(msg) = self.backend.next_incoming()? {
            match self.process_incoming_plain(msg, state).await {
                Ok(new) => state = new,
                Err(e) => {
                    self.state = Err(e.clone());
                    return Err(e);
                }
            }
        }

        while let Some(msg) = self.backend.next_outgoing()? {
            self.queue_tls_message(msg);
        }

        self.state = Ok(state);

        Ok(self.common_state.current_io_state())
    }

    async fn process_new_handshake_messages(
        &mut self,
        mut state: Box<dyn State>,
    ) -> Result<Box<dyn State>, Error> {
        self.common_state.aligned_handshake = self.handshake_joiner.is_empty();
        while let Some(msg) = self.handshake_joiner.frames.pop_front() {
            state = self.common_state.process_main_protocol(msg, state).await?;
        }

        Ok(state)
    }

    /// Writes plaintext `buf` into an internal buffer. May not fully process the
    /// whole buffer and returns the processed length.
    pub fn write_plaintext(&mut self, buf: &[u8]) -> Result<usize, Error> {
        if buf.is_empty() {
            // Don't send empty fragments.
            return Ok(0);
        }

        let len = self.sendable_plaintext.append_limited_copy(buf);
        Ok(len)
    }

    /// Read TLS content from `rd`.  This method does internal
    /// buffering, so `rd` can supply TLS messages in arbitrary-
    /// sized chunks (like a socket or pipe might).
    ///
    /// You should call [`process_new_packets`] each time a call to
    /// this function succeeds.
    ///
    /// The returned error only relates to IO on `rd`.  TLS-level
    /// errors are emitted from [`process_new_packets`].
    ///
    /// This function returns `Ok(0)` when the underlying `rd` does
    /// so.  This typically happens when a socket is cleanly closed,
    /// or a file is at EOF.
    ///
    /// [`process_new_packets`]: ClientConnection::process_new_packets
    pub fn read_tls(&mut self, rd: &mut dyn io::Read) -> Result<usize, io::Error> {
        self.message_deframer.read(rd)
    }
}

impl Deref for ClientConnection {
    type Target = CommonState;

    fn deref(&self) -> &Self::Target {
        &self.common_state
    }
}

impl DerefMut for ClientConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.common_state
    }
}

/// Connection state.
pub struct CommonState {
    pub(crate) negotiated_version: Option<ProtocolVersion>,
    pub(crate) backend: MpcTlsLeader,
    /// Whether outgoing records are encrypted, activated by the CCS we send.
    encrypting: bool,
    /// Whether incoming records are decrypted, activated by the CCS the
    /// server sends.
    decrypting: bool,
    pub(crate) suite: Option<SupportedCipherSuite>,
    pub(crate) alpn_protocol: Option<Vec<u8>>,
    aligned_handshake: bool,
    pub(crate) may_send_application_data: bool,
    pub(crate) may_receive_application_data: bool,
    sent_fatal_alert: bool,
    /// If the peer has sent close_notify.
    has_received_close_notify: bool,
    received_middlebox_ccs: u8,
    message_fragmenter: MessageFragmenter,
    received_plaintext: ChunkVecBuffer,
    sendable_plaintext: ChunkVecBuffer,
    pub(crate) sendable_tls: ChunkVecBuffer,
}

impl CommonState {
    pub(crate) fn new(
        max_fragment_size: Option<usize>,
        backend: MpcTlsLeader,
    ) -> Result<Self, Error> {
        Ok(Self {
            negotiated_version: None,
            backend,
            encrypting: false,
            decrypting: false,
            suite: None,
            alpn_protocol: None,
            aligned_handshake: true,
            may_send_application_data: false,
            may_receive_application_data: false,
            sent_fatal_alert: false,
            has_received_close_notify: false,
            received_middlebox_ccs: 0,
            message_fragmenter: MessageFragmenter::new(max_fragment_size)
                .map_err(|_| Error::BadMaxFragmentSize)?,
            received_plaintext: ChunkVecBuffer::new(Some(0)),
            sendable_plaintext: ChunkVecBuffer::new(Some(DEFAULT_BUFFER_LIMIT)),
            sendable_tls: ChunkVecBuffer::new(Some(DEFAULT_BUFFER_LIMIT)),
        })
    }

    /// Returns true if the caller should call [`CommonState::write_tls`] as
    /// soon as possible.
    pub fn wants_write(&self) -> bool {
        !self.sendable_tls.is_empty()
    }

    /// Returns true if there is no plaintext data available to read
    /// immediately.
    pub fn plaintext_is_empty(&self) -> bool {
        self.received_plaintext.is_empty()
    }

    /// Returns true if the buffer for sendable plaintext is full.
    pub fn sendable_plaintext_is_full(&self) -> bool {
        self.sendable_plaintext.is_full()
    }

    /// Returns true if the connection is currently performing the TLS
    /// handshake.
    ///
    /// During this time plaintext written to the connection is buffered in
    /// memory. After [`ClientConnection::process_new_packets`] has been called,
    /// this might start to return `false` while the final handshake packets
    /// still need to be extracted from the connection's buffers.
    pub fn is_handshaking(&self) -> bool {
        !(self.may_send_application_data && self.may_receive_application_data)
    }

    pub(crate) fn is_tls13(&self) -> bool {
        matches!(self.negotiated_version, Some(ProtocolVersion::TLSv1_3))
    }

    async fn process_main_protocol(
        &mut self,
        msg: Message,
        mut state: Box<dyn State>,
    ) -> Result<Box<dyn State>, Error> {
        // For TLS1.2, outside of the handshake, send rejection alerts for
        // renegotiation requests.  These can occur any time.
        if self.may_receive_application_data
            && !self.is_tls13()
            && msg.is_handshake_type(HandshakeType::HelloRequest)
        {
            self.send_warning_alert(AlertDescription::NoRenegotiation)
                .await?;
            return Ok(state);
        }

        match state.handle(self, msg).await {
            Ok(next) => {
                state = next;
                Ok(state)
            }
            Err(e @ Error::InappropriateMessage { .. })
            | Err(e @ Error::InappropriateHandshakeMessage { .. }) => {
                self.send_fatal_alert(AlertDescription::UnexpectedMessage)
                    .await?;
                Err(e)
            }
            Err(e) => Err(e),
        }
    }

    // Changing the keys must not span any fragmented handshake
    // messages.  Otherwise the defragmented messages will have
    // been protected with two different record layer protections,
    // which is illegal.  Not mentioned in RFC.
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

    /// Starts encrypting outgoing records. Called when we send our
    /// ChangeCipherSpec.
    pub(crate) fn start_encrypting(&mut self) {
        self.encrypting = true;
    }

    /// Starts decrypting incoming records. Called when the server's
    /// ChangeCipherSpec is received.
    pub(crate) fn start_decrypting(&mut self) {
        self.decrypting = true;
    }

    pub(crate) async fn decrypt_incoming(&mut self, encr: OpaqueMessage) -> Result<(), Error> {
        debug_assert!(self.decrypting);
        self.backend.push_incoming(encr).await?;

        Ok(())
    }

    /// Fragment `m`, encrypt the fragments, and then queue
    /// the encrypted fragments for sending.
    ///
    /// Unlike upstream rustls there is no sequence-space exhaustion guard:
    /// the MPC record layer enforces the configured traffic limits, which
    /// bound the number of records far below the sequence space.
    pub(crate) async fn send_msg_encrypt(&mut self, m: PlainMessage) -> Result<(), Error> {
        let mut plain_messages = VecDeque::new();
        self.message_fragmenter.fragment(m, &mut plain_messages);

        for m in plain_messages {
            self.send_single_fragment(m).await?;
        }
        Ok(())
    }

    /// Like send_msg_encrypt, but operate on an appdata directly.
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
        self.backend.push_outgoing(m).await?;

        Ok(())
    }

    /// Writes TLS messages to `wr`.
    ///
    /// On success, this function returns `Ok(n)` where `n` is a number of bytes
    /// written to `wr` (after encoding and encryption).
    ///
    /// After this function returns, the connection buffer may not yet be fully
    /// flushed. The [`CommonState::wants_write`] function can be used to
    /// check if the output buffer is empty.
    pub fn write_tls(&mut self, wr: &mut dyn io::Write) -> Result<usize, io::Error> {
        self.sendable_tls.write_to(wr)
    }

    pub(crate) async fn start_outgoing_traffic(&mut self) -> Result<(), Error> {
        self.may_send_application_data = true;
        self.flush_plaintext().await
    }

    pub(crate) async fn start_traffic(&mut self) -> Result<(), Error> {
        self.may_receive_application_data = true;
        self.backend.start_traffic().await?;
        self.start_outgoing_traffic().await
    }

    /// Send and encrypt any buffered plaintext. Does nothing during handshake.
    pub(crate) async fn flush_plaintext(&mut self) -> Result<(), Error> {
        if !self.may_send_application_data {
            return Ok(());
        }

        while let Some(buf) = self.sendable_plaintext.pop() {
            self.send_appdata_encrypt(&buf).await?;
        }

        Ok(())
    }

    // Put m into sendable_tls for writing.
    pub(crate) fn queue_tls_message(&mut self, m: OpaqueMessage) {
        self.sendable_tls.append(m.encode());
    }

    /// Send a raw TLS message, fragmenting it if needed.
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
        // Reject unknown AlertLevels.
        if let AlertLevel::Unknown(_) = alert.level {
            self.send_fatal_alert(AlertDescription::IllegalParameter)
                .await?;
        }

        // If we get a CloseNotify, make a note to declare EOF to our
        // caller.
        if alert.description == AlertDescription::CloseNotify {
            self.has_received_close_notify = true;
            return Ok(());
        }

        // Warnings are nonfatal for TLS1.2, but outlawed in TLS1.3
        // (except, for no good reason, user_cancelled).
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
        self.send_msg(m, self.encrypting).await?;
        self.sent_fatal_alert = true;
        Ok(())
    }

    /// Queues a close_notify warning alert to be sent in the next
    /// [`CommonState::write_tls`] call.  This informs the peer that the
    /// connection is being closed.
    pub async fn send_close_notify(&mut self) -> Result<(), Error> {
        debug!("Sending warning alert {:?}", AlertDescription::CloseNotify);
        self.send_warning_alert_no_log(AlertDescription::CloseNotify)
            .await
    }

    async fn send_warning_alert_no_log(&mut self, desc: AlertDescription) -> Result<(), Error> {
        let m = Message::build_alert(AlertLevel::Warning, desc);
        self.send_msg(m, self.encrypting).await
    }

    /// Returns true if the caller should call [`ClientConnection::read_tls`] as soon
    /// as possible.
    ///
    /// If there is pending plaintext data to read with
    /// [`ClientConnection::read_plaintext`], this returns false.  If the
    /// application respects this mechanism, only one full TLS message will
    /// be buffered.
    pub fn wants_read(&self) -> bool {
        // We want to read more data all the time, except when we have unprocessed
        // plaintext. This provides back-pressure to the TCP buffers. We also
        // don't want to read more after the peer has sent us a close
        // notification.
        //
        // In the handshake case we don't have readable plaintext before the handshake
        // has completed, but also don't want to read if we still have sendable
        // tls.
        self.received_plaintext.is_empty()
            && !self.has_received_close_notify
            && (self.may_send_application_data || self.sendable_tls.is_empty())
    }

    /// Enables or disables the decryption of incoming messages.
    pub fn enable_decryption(&mut self, enable: bool) {
        self.backend.enable_decryption(enable);
    }

    /// Returns the context and transcript after the connection is closed.
    ///
    /// Returns `None` if the connection is not closed yet.
    pub fn finish(
        &mut self,
    ) -> Option<(mpz_common::Context, tlsn_core::transcript::TlsTranscript)> {
        self.backend.finish()
    }

    fn current_io_state(&self) -> IoState {
        IoState {
            tls_bytes_to_write: self.sendable_tls.len(),
            plaintext_bytes_to_read: self.received_plaintext.len(),
        }
    }
}

/// A state of the TLS protocol state machine.
#[async_trait]
pub(crate) trait State: Send + Sync {
    async fn start(self: Box<Self>, _cx: &mut CommonState) -> Result<Box<dyn State>, Error> {
        panic!("Start called on unexpected state")
    }

    async fn handle(
        self: Box<Self>,
        cx: &mut CommonState,
        message: Message,
    ) -> Result<Box<dyn State>, Error>;
}

const DEFAULT_BUFFER_LIMIT: usize = 64 * 1024;
