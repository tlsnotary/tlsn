#[cfg(feature = "logging")]
use crate::log::{debug, error, trace, warn};
use crate::{
    backend::{Backend, RustCryptoBackend},
    client::ClientConnectionData,
    error::Error,
    record_layer,
    vecbuf::ChunkVecBuffer,
};
use async_trait::async_trait;
use futures::{AsyncRead, AsyncWrite};
use std::{
    collections::VecDeque,
    convert::TryFrom,
    io, mem,
    ops::{Deref, DerefMut},
};
use tls_backend::BackendNotify;
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

/// Values of this structure are returned from [`Connection::process_new_packets`]
/// and tell the caller the current I/O state of the TLS connection.
#[derive(Debug, PartialEq)]
pub struct IoState {
    tls_bytes_to_write: usize,
    plaintext_bytes_to_read: usize,
    peer_has_closed: bool,
}

impl IoState {
    /// How many bytes could be written by [`CommonState::write_tls`] if called
    /// right now.  A non-zero value implies [`CommonState::wants_write`].
    pub fn tls_bytes_to_write(&self) -> usize {
        self.tls_bytes_to_write
    }

    /// How many plaintext bytes could be obtained via [`std::io::Read`]
    /// without further I/O.
    pub fn plaintext_bytes_to_read(&self) -> usize {
        self.plaintext_bytes_to_read
    }

    /// True if the peer has sent us a close_notify alert.  This is
    /// the TLS mechanism to securely half-close a TLS connection,
    /// and signifies that the peer will not send any further data
    /// on this connection.
    ///
    /// This is also signalled via returning `Ok(0)` from
    /// [`std::io::Read`], after all the received bytes have been
    /// retrieved.
    pub fn peer_has_closed(&self) -> bool {
        self.peer_has_closed
    }
}

/// A structure that implements [`std::io::Read`] for reading plaintext.
pub struct Reader<'a> {
    received_plaintext: &'a mut ChunkVecBuffer,
    peer_cleanly_closed: bool,
    has_seen_eof: bool,
}

impl<'a> io::Read for Reader<'a> {
    /// Obtain plaintext data received from the peer over this TLS connection.
    ///
    /// If the peer closes the TLS session cleanly, this returns `Ok(0)`  once all
    /// the pending data has been read. No further data can be received on that
    /// connection, so the underlying TCP connection should be half-closed too.
    ///
    /// If the peer closes the TLS session uncleanly (a TCP EOF without sending a
    /// `close_notify` alert) this function returns `Err(ErrorKind::UnexpectedEof.into())`
    /// once any pending data has been read.
    ///
    /// Note that support for `close_notify` varies in peer TLS libraries: many do not
    /// support it and uncleanly close the TCP connection (this might be
    /// vulnerable to truncation attacks depending on the application protocol).
    /// This means applications using rustls must both handle EOF
    /// from this function, *and* unexpected EOF of the underlying TCP connection.
    ///
    /// If there are no bytes to read, this returns `Err(ErrorKind::WouldBlock.into())`.
    ///
    /// You may learn the number of bytes available at any time by inspecting
    /// the return of [`Connection::process_new_packets`].
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = self.received_plaintext.read(buf)?;

        if len == 0 && !buf.is_empty() {
            // No bytes available:
            match (self.peer_cleanly_closed, self.has_seen_eof) {
                // cleanly closed; don't care about TCP EOF: express this as Ok(0)
                (true, _) => {}
                // unclean closure
                (false, true) => return Err(io::ErrorKind::UnexpectedEof.into()),
                // connection still going, but need more data: signal `WouldBlock` so that
                // the caller knows this
                (false, false) => return Err(io::ErrorKind::WouldBlock.into()),
            }
        }

        Ok(len)
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub(crate) enum Protocol {
    Tcp,
}

#[derive(Debug)]
pub(crate) struct ConnectionRandoms {
    pub(crate) client: [u8; 32],
    pub(crate) server: [u8; 32],
}

/// How many ChangeCipherSpec messages we accept and drop in TLS1.3 handshakes.
/// The spec says 1, but implementations (namely the boringssl test suite) get
/// this wrong.  BoringSSL itself accepts up to 32.
static TLS13_MAX_DROPPED_CCS: u8 = 2u8;

impl ConnectionRandoms {
    pub(crate) fn new(client: Random, server: Random) -> Self {
        Self {
            client: client.0,
            server: server.0,
        }
    }
}

// --- Common (to client and server) connection functions ---

fn is_valid_ccs(msg: &OpaqueMessage) -> bool {
    // nb. this is prior to the record layer, so is unencrypted. see
    // third paragraph of section 5 in RFC8446.
    msg.typ == ContentType::ChangeCipherSpec && msg.payload.0 == [0x01]
}

enum Limit {
    Yes,
    No,
}

/// Interface shared by client and server connections.
pub struct ConnectionCommon {
    state: Result<Box<dyn State<ClientConnectionData>>, Error>,
    pub(crate) data: ClientConnectionData,
    pub(crate) common_state: CommonState,
    message_deframer: MessageDeframer,
    handshake_joiner: HandshakeJoiner,
}

impl ConnectionCommon {
    pub(crate) fn new(
        state: Box<dyn State<ClientConnectionData>>,
        data: ClientConnectionData,
        common_state: CommonState,
    ) -> Self {
        Self {
            state: Ok(state),
            data,
            common_state,
            message_deframer: MessageDeframer::new(),
            handshake_joiner: HandshakeJoiner::new(),
        }
    }

    /// Returns an object that allows reading plaintext.
    pub fn reader(&mut self) -> Reader {
        Reader {
            received_plaintext: &mut self.common_state.received_plaintext,
            // Are we done? i.e., have we processed all received messages, and received a
            // close_notify to indicate that no new messages will arrive?
            peer_cleanly_closed: self.common_state.has_received_close_notify
                && !self.message_deframer.has_pending(),
            has_seen_eof: self.common_state.has_seen_eof,
        }
    }

    /// Reads out any buffered plaintext received from the peer. Returns the
    /// number of bytes read.
    pub fn read_plaintext(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.common_state.received_plaintext.read(buf)
    }

    /// Returns the number of messages buffered for decryption.
    pub async fn buffer_len(&mut self) -> Result<usize, Error> {
        self.common_state
            .backend
            .buffer_len()
            .await
            .map_err(Error::from)
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
        let mut cx = Context {
            common: &mut self.common_state,
            data: &mut self.data,
        };
        self.state = state.start(&mut cx).await;
        Ok(())
    }

    /// Signals that the server has closed the connection.
    pub async fn server_closed(&mut self) -> Result<(), Error> {
        self.common_state.backend.server_closed().await?;
        Ok(())
    }

    /// This function uses `io` to complete any outstanding IO for
    /// this connection.
    ///
    /// This is a convenience function which solely uses other parts
    /// of the public API.
    ///
    /// What this means depends on the connection  state:
    ///
    /// - If the connection [`is_handshaking`], then IO is performed until
    ///   the handshake is complete.
    /// - Otherwise, if [`wants_write`] is true, [`write_tls`] is invoked
    ///   until it is all written.
    /// - Otherwise, if [`wants_read`] is true, [`read_tls`] is invoked
    ///   once.
    ///
    /// The return value is the number of bytes read from and written
    /// to `io`, respectively.
    ///
    /// This function will block if `io` blocks.
    ///
    /// Errors from TLS record handling (i.e., from [`process_new_packets`])
    /// are wrapped in an `io::ErrorKind::InvalidData`-kind error.
    ///
    /// [`is_handshaking`]: CommonState::is_handshaking
    /// [`wants_read`]: CommonState::wants_read
    /// [`wants_write`]: CommonState::wants_write
    /// [`write_tls`]: CommonState::write_tls
    /// [`read_tls`]: ConnectionCommon::read_tls
    /// [`process_new_packets`]: ConnectionCommon::process_new_packets
    pub async fn complete_io<T>(&mut self, io: &mut T) -> Result<(usize, usize), io::Error>
    where
        Self: Sized,
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let until_handshaked = self.is_handshaking();
        let mut eof = false;
        let mut wrlen = 0;
        let mut rdlen = 0;

        loop {
            while self.wants_write() {
                wrlen += self.write_tls_async(io).await?;
            }

            if !until_handshaked && wrlen > 0 {
                return Ok((rdlen, wrlen));
            }

            if !eof && self.wants_read() {
                match self.read_tls_async(io).await? {
                    0 => eof = true,
                    n => rdlen += n,
                }
            }

            match self.process_new_packets().await {
                Ok(_) => {}
                Err(e) => {
                    // In case we have an alert to send describing this error,
                    // try a last-gasp write -- but don't predate the primary
                    // error.
                    let _ignored = self.write_tls_async(io).await;

                    return Err(io::Error::new(io::ErrorKind::InvalidData, e));
                }
            };

            match (eof, until_handshaked, self.is_handshaking()) {
                (_, true, false) => return Ok((rdlen, wrlen)),
                (_, false, _) => return Ok((rdlen, wrlen)),
                (true, true, true) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
                (..) => {}
            }
        }
    }

    /// Extract the first handshake message.
    ///
    /// This is a shortcut to the `process_new_packets()` -> `process_msg()` ->
    /// `process_handshake_messages()` path, specialized for the first handshake message.
    pub(crate) async fn first_handshake_message(&mut self) -> Result<Option<Message>, Error> {
        if self.message_deframer.desynced {
            return Err(Error::CorruptMessage);
        }

        let msg = match self.message_deframer.frames.pop_front() {
            Some(msg) => msg,
            None => return Ok(None),
        };

        let msg = msg.into_plain_message();
        if !self.handshake_joiner.want_message(&msg) {
            return Err(Error::CorruptMessagePayload(ContentType::Handshake));
        }

        if self.handshake_joiner.take_message(msg).is_none() {
            self.common_state
                .send_fatal_alert(AlertDescription::DecodeError)
                .await?;
            return Err(Error::CorruptMessagePayload(ContentType::Handshake));
        }

        self.common_state.aligned_handshake = self.handshake_joiner.is_empty();
        Ok(self.handshake_joiner.frames.pop_front())
    }

    pub(crate) fn replace_state(&mut self, new: Box<dyn State<ClientConnectionData>>) {
        self.state = Ok(new);
    }

    async fn process_msg(
        &mut self,
        msg: OpaqueMessage,
        state: Box<dyn State<ClientConnectionData>>,
    ) -> Result<Box<dyn State<ClientConnectionData>>, Error> {
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
                return Ok(state);
            }
        }

        // Decrypt if demanded by current state.
        let msg = match self.common_state.record_layer.is_decrypting() {
            true => match self.common_state.decrypt_incoming(msg).await {
                Ok(None) => {
                    // message dropped
                    return Ok(state);
                }
                Err(e) => {
                    return Err(e);
                }
                Ok(Some(msg)) => msg,
            },
            false => msg.into_plain_message(),
        };

        // For handshake messages, we need to join them before parsing
        // and processing.
        if self.handshake_joiner.want_message(&msg) {
            // First decryptable handshake message concludes trial decryption
            self.common_state.record_layer.finish_trial_decryption();

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

        self.common_state
            .process_main_protocol(msg, state, &mut self.data)
            .await
    }

    /// Returns a notification future which resolves when the backend has messages ready to decrypt.
    pub async fn get_notify(&mut self) -> Result<BackendNotify, Error> {
        self.common_state
            .backend
            .get_notify()
            .await
            .map_err(Error::from)
    }

    /// Processes any new packets read by a previous call to
    /// [`Connection::read_tls`].
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
    /// [`read_tls`]: Connection::read_tls
    /// [`process_new_packets`]: Connection::process_new_packets
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

        while let Some(msg) = self.message_deframer.frames.pop_front() {
            self.backend.buffer_incoming(msg).await?;
        }

        while let Some(msg) = self.backend.next_incoming().await? {
            match self.process_msg(msg, state).await {
                Ok(new) => state = new,
                Err(e) => {
                    self.state = Err(e.clone());
                    return Err(e);
                }
            }
        }

        self.state = Ok(state);
        Ok(self.common_state.current_io_state())
    }

    async fn process_new_handshake_messages(
        &mut self,
        mut state: Box<dyn State<ClientConnectionData>>,
    ) -> Result<Box<dyn State<ClientConnectionData>>, Error> {
        self.common_state.aligned_handshake = self.handshake_joiner.is_empty();
        while let Some(msg) = self.handshake_joiner.frames.pop_front() {
            state = self
                .common_state
                .process_main_protocol(msg, state, &mut self.data)
                .await?;
        }

        Ok(state)
    }

    /// Write buffer into connection
    pub async fn write_plaintext(&mut self, buf: &[u8]) -> Result<usize, Error> {
        if let Ok(st) = &mut self.state {
            st.perhaps_write_key_update(&mut self.common_state).await;
        }
        self.common_state.send_some_plaintext(buf).await
    }

    /// Write entire buffer into connection
    pub async fn write_all_plaintext(&mut self, buf: &[u8]) -> Result<usize, Error> {
        let mut pos = 0;
        while pos < buf.len() {
            pos += self.write_plaintext(&buf[pos..]).await?;
        }
        Ok(pos)
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
    /// [`process_new_packets`]: Connection::process_new_packets
    pub fn read_tls(&mut self, rd: &mut dyn io::Read) -> Result<usize, io::Error> {
        let res = self.message_deframer.read(rd);
        if let Ok(0) = res {
            self.common_state.has_seen_eof = true;
        }
        res
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
    /// [`process_new_packets`]: Connection::process_new_packets
    pub async fn read_tls_async<T: AsyncRead + Unpin>(
        &mut self,
        rd: &mut T,
    ) -> Result<usize, io::Error> {
        let res = self.message_deframer.read_async(rd).await;
        if let Ok(0) = res {
            self.common_state.has_seen_eof = true;
        }
        res
    }

    /// Derives key material from the agreed connection secrets.
    ///
    /// This function fills in `output` with `output.len()` bytes of key
    /// material derived from the master session secret using `label`
    /// and `context` for diversification.
    ///
    /// See RFC5705 for more details on what this does and is for.
    ///
    /// For TLS1.3 connections, this function does not use the
    /// "early" exporter at any point.
    ///
    /// This function fails if called prior to the handshake completing;
    /// check with [`CommonState::is_handshaking`] first.
    pub fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Result<(), Error> {
        match self.state.as_ref() {
            Ok(st) => st.export_keying_material(output, label, context),
            Err(e) => Err(e.clone()),
        }
    }
}

impl Deref for ConnectionCommon {
    type Target = CommonState;

    fn deref(&self) -> &Self::Target {
        &self.common_state
    }
}

impl DerefMut for ConnectionCommon {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.common_state
    }
}

/// Connection state common to both client and server connections.
pub struct CommonState {
    pub(crate) negotiated_version: Option<ProtocolVersion>,
    pub(crate) side: Side,
    pub(crate) record_layer: record_layer::RecordLayer,
    pub(crate) backend: Box<dyn Backend>,
    pub(crate) suite: Option<SupportedCipherSuite>,
    pub(crate) alpn_protocol: Option<Vec<u8>>,
    aligned_handshake: bool,
    pub(crate) may_send_application_data: bool,
    pub(crate) may_receive_application_data: bool,
    pub(crate) early_traffic: bool,
    sent_fatal_alert: bool,
    /// If the peer has sent close_notify.
    has_received_close_notify: bool,
    /// If the peer has signaled end of stream.
    has_seen_eof: bool,
    received_middlebox_ccs: u8,
    pub(crate) peer_certificates: Option<Vec<tls_core::key::Certificate>>,
    message_fragmenter: MessageFragmenter,
    received_plaintext: ChunkVecBuffer,
    sendable_plaintext: ChunkVecBuffer,
    pub(crate) sendable_tls: ChunkVecBuffer,
    #[allow(dead_code)]
    /// Protocol whose key schedule should be used. Unused for TLS < 1.3.
    pub(crate) protocol: Protocol,
}

impl CommonState {
    pub(crate) fn new(
        max_fragment_size: Option<usize>,
        side: Side,
        backend: Box<dyn Backend>,
    ) -> Result<Self, Error> {
        Ok(Self {
            negotiated_version: None,
            side,
            record_layer: record_layer::RecordLayer::new(),
            backend,
            suite: None,
            alpn_protocol: None,
            aligned_handshake: true,
            may_send_application_data: false,
            may_receive_application_data: false,
            early_traffic: false,
            sent_fatal_alert: false,
            has_received_close_notify: false,
            has_seen_eof: false,
            received_middlebox_ccs: 0,
            peer_certificates: None,
            message_fragmenter: MessageFragmenter::new(max_fragment_size)
                .map_err(|_| Error::BadMaxFragmentSize)?,
            received_plaintext: ChunkVecBuffer::new(Some(0)),
            sendable_plaintext: ChunkVecBuffer::new(Some(DEFAULT_BUFFER_LIMIT)),
            sendable_tls: ChunkVecBuffer::new(Some(DEFAULT_BUFFER_LIMIT)),

            protocol: Protocol::Tcp,
        })
    }

    /// Returns true if the caller should call [`CommonState::write_tls`] as soon
    /// as possible.
    pub fn wants_write(&self) -> bool {
        !self.sendable_tls.is_empty()
    }

    /// Returns true if there is no plaintext data available to read immediately.
    pub fn plaintext_is_empty(&self) -> bool {
        self.received_plaintext.is_empty()
    }

    /// Returns true if the connection is currently performing the TLS handshake.
    ///
    /// During this time plaintext written to the connection is buffered in memory. After
    /// [`Connection::process_new_packets`] has been called, this might start to return `false`
    /// while the final handshake packets still need to be extracted from the connection's buffers.
    pub fn is_handshaking(&self) -> bool {
        !(self.may_send_application_data && self.may_receive_application_data)
    }

    /// Retrieves the certificate chain used by the peer to authenticate.
    ///
    /// The order of the certificate chain is as it appears in the TLS
    /// protocol: the first certificate relates to the peer, the
    /// second certifies the first, the third certifies the second, and
    /// so on.
    ///
    /// This is made available for both full and resumed handshakes.
    ///
    /// For clients, this is the certificate chain of the server.
    ///
    /// For servers, this is the certificate chain of the client,
    /// if client authentication was completed.
    ///
    /// The return value is None until this value is available.
    pub fn peer_certificates(&self) -> Option<&[tls_core::key::Certificate]> {
        self.peer_certificates.as_deref()
    }

    /// Retrieves the protocol agreed with the peer via ALPN.
    ///
    /// A return value of `None` after handshake completion
    /// means no protocol was agreed (because no protocols
    /// were offered or accepted by the peer).
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.get_alpn_protocol()
    }

    /// Retrieves the ciphersuite agreed with the peer.
    ///
    /// This returns None until the ciphersuite is agreed.
    pub fn negotiated_cipher_suite(&self) -> Option<SupportedCipherSuite> {
        self.suite
    }

    /// Retrieves the protocol version agreed with the peer.
    ///
    /// This returns `None` until the version is agreed.
    pub fn protocol_version(&self) -> Option<ProtocolVersion> {
        self.negotiated_version
    }

    pub(crate) fn is_tls13(&self) -> bool {
        matches!(self.negotiated_version, Some(ProtocolVersion::TLSv1_3))
    }

    async fn process_main_protocol(
        &mut self,
        msg: Message,
        mut state: Box<dyn State<ClientConnectionData>>,
        data: &mut ClientConnectionData,
    ) -> Result<Box<dyn State<ClientConnectionData>>, Error> {
        // For TLS1.2, outside of the handshake, send rejection alerts for
        // renegotiation requests.  These can occur any time.
        if self.may_receive_application_data && !self.is_tls13() {
            let reject_ty = match self.side {
                Side::Client => HandshakeType::HelloRequest,
            };
            if msg.is_handshake_type(reject_ty) {
                self.send_warning_alert(AlertDescription::NoRenegotiation)
                    .await?;
                return Ok(state);
            }
        }

        let mut cx = Context { common: self, data };
        match state.handle(&mut cx, msg).await {
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

    /// Send plaintext application data, fragmenting and
    /// encrypting it as it goes out.
    ///
    /// If internal buffers are too small, this function will not accept
    /// all the data.
    pub(crate) async fn send_some_plaintext(&mut self, data: &[u8]) -> Result<usize, Error> {
        self.send_plain(data, Limit::Yes).await
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

    pub(crate) async fn decrypt_incoming(
        &mut self,
        encr: OpaqueMessage,
    ) -> Result<Option<PlainMessage>, Error> {
        if self.record_layer.wants_close_before_decrypt() {
            self.send_close_notify().await?;
        }

        let encrypted_len = encr.payload.0.len();
        let plain = self
            .record_layer
            .decrypt_incoming(self.backend.as_mut(), encr)
            .await;

        match plain {
            Err(Error::PeerSentOversizedRecord) => {
                self.send_fatal_alert(AlertDescription::RecordOverflow)
                    .await?;
                Err(Error::PeerSentOversizedRecord)
            }
            Err(Error::DecryptError) if self.record_layer.doing_trial_decryption(encrypted_len) => {
                trace!("Dropping undecryptable message after aborted early_data");
                Ok(None)
            }
            Err(Error::DecryptError) => {
                self.send_fatal_alert(AlertDescription::BadRecordMac)
                    .await?;
                Err(Error::DecryptError)
            }
            Err(e) => Err(e),
            Ok(plain) => Ok(Some(plain)),
        }
    }

    /// Fragment `m`, encrypt the fragments, and then queue
    /// the encrypted fragments for sending.
    pub(crate) async fn send_msg_encrypt(&mut self, m: PlainMessage) -> Result<(), Error> {
        let mut plain_messages = VecDeque::new();
        self.message_fragmenter.fragment(m, &mut plain_messages);

        // Close connection once we start to run out of
        // sequence space.
        if self.record_layer.wants_close_before_encrypt() {
            debug!("Sending warning alert {:?}", AlertDescription::CloseNotify);
            let m = Message::build_alert(AlertLevel::Warning, AlertDescription::CloseNotify);
            self.send_single_fragment(m.into()).await?;
        }

        for m in plain_messages {
            self.send_single_fragment(m).await?;
        }
        Ok(())
    }

    /// Like send_msg_encrypt, but operate on an appdata directly.
    async fn send_appdata_encrypt(&mut self, payload: &[u8], limit: Limit) -> Result<usize, Error> {
        // Here, the limit on sendable_tls applies to encrypted data,
        // but we're respecting it for plaintext data -- so we'll
        // be out by whatever the cipher+record overhead is.  That's a
        // constant and predictable amount, so it's not a terrible issue.
        let len = match limit {
            Limit::Yes => self.sendable_tls.apply_limit(payload.len()),
            Limit::No => payload.len(),
        };

        let mut plain_messages = VecDeque::new();
        self.message_fragmenter.fragment(
            PlainMessage {
                typ: ContentType::ApplicationData,
                version: ProtocolVersion::TLSv1_2,
                payload: Payload::new(&payload[..len]),
            },
            &mut plain_messages,
        );

        for m in plain_messages {
            self.send_single_fragment(m).await?;
        }

        Ok(len)
    }

    async fn send_single_fragment(&mut self, m: PlainMessage) -> Result<(), Error> {
        // Refuse to wrap counter at all costs.  This
        // is basically untestable unfortunately.
        if self.record_layer.encrypt_exhausted() {
            return Err(Error::EncryptError);
        }

        let em = self
            .record_layer
            .encrypt_outgoing(self.backend.as_mut(), m)
            .await?;
        self.queue_tls_message(em);
        Ok(())
    }

    /// Writes TLS messages to `wr`.
    ///
    /// On success, this function returns `Ok(n)` where `n` is a number of bytes written to `wr`
    /// (after encoding and encryption).
    ///
    /// After this function returns, the connection buffer may not yet be fully flushed. The
    /// [`CommonState::wants_write`] function can be used to check if the output buffer is empty.
    pub fn write_tls(&mut self, wr: &mut dyn io::Write) -> Result<usize, io::Error> {
        self.sendable_tls.write_to(wr)
    }

    /// Writes TLS messages to `wr`.
    ///
    /// On success, this function returns `Ok(n)` where `n` is a number of bytes written to `wr`
    /// (after encoding and encryption).
    ///
    /// After this function returns, the connection buffer may not yet be fully flushed. The
    /// [`CommonState::wants_write`] function can be used to check if the output buffer is empty.
    pub async fn write_tls_async<T: AsyncWrite + Unpin>(
        &mut self,
        wr: &mut T,
    ) -> Result<usize, io::Error> {
        self.sendable_tls.write_to_async(wr).await
    }

    /// Encrypt and send some plaintext `data`.  `limit` controls
    /// whether the per-connection buffer limits apply.
    ///
    /// Returns the number of bytes written from `data`: this might
    /// be less than `data.len()` if buffer limits were exceeded.
    async fn send_plain(&mut self, data: &[u8], limit: Limit) -> Result<usize, Error> {
        if !self.may_send_application_data {
            // If we haven't completed handshaking, buffer
            // plaintext to send once we do.
            let len = match limit {
                Limit::Yes => self.sendable_plaintext.append_limited_copy(data),
                Limit::No => self.sendable_plaintext.append(data.to_vec()),
            };
            return Ok(len);
        }

        debug_assert!(self.record_layer.is_encrypting());

        if data.is_empty() {
            // Don't send empty fragments.
            return Ok(0);
        }

        self.send_appdata_encrypt(data, limit).await
    }

    pub(crate) async fn start_outgoing_traffic(&mut self) -> Result<(), Error> {
        self.may_send_application_data = true;
        self.flush_plaintext().await
    }

    pub(crate) async fn start_traffic(&mut self) -> Result<(), Error> {
        self.may_receive_application_data = true;
        self.start_outgoing_traffic().await
    }

    /// Sets a limit on the internal buffers used to buffer
    /// unsent plaintext (prior to completing the TLS handshake)
    /// and unsent TLS records.  This limit acts only on application
    /// data written through [`Connection::writer`].
    ///
    /// By default the limit is 64KB.  The limit can be set
    /// at any time, even if the current buffer use is higher.
    ///
    /// [`None`] means no limit applies, and will mean that written
    /// data is buffered without bound -- it is up to the application
    /// to appropriately schedule its plaintext and TLS writes to bound
    /// memory usage.
    ///
    /// For illustration: `Some(1)` means a limit of one byte applies:
    /// [`Connection::writer`] will accept only one byte, encrypt it and
    /// add a TLS header.  Once this is sent via [`CommonState::write_tls`],
    /// another byte may be sent.
    ///
    /// # Internal write-direction buffering
    /// rustls has two buffers whose size are bounded by this setting:
    ///
    /// ## Buffering of unsent plaintext data prior to handshake completion
    ///
    /// Calls to [`Connection::writer`] before or during the handshake
    /// are buffered (up to the limit specified here).  Once the
    /// handshake completes this data is encrypted and the resulting
    /// TLS records are added to the outgoing buffer.
    ///
    /// ## Buffering of outgoing TLS records
    ///
    /// This buffer is used to store TLS records that rustls needs to
    /// send to the peer.  It is used in these two circumstances:
    ///
    /// - by [`Connection::process_new_packets`] when a handshake or alert
    ///   TLS record needs to be sent.
    /// - by [`Connection::writer`] post-handshake: the plaintext is
    ///   encrypted and the resulting TLS record is buffered.
    ///
    /// This buffer is emptied by [`CommonState::write_tls`].
    pub fn set_buffer_limit(&mut self, limit: Option<usize>) {
        self.sendable_plaintext.set_limit(limit);
        self.sendable_tls.set_limit(limit);
    }

    /// Send any buffered plaintext.  Plaintext is buffered if
    /// written during handshake.
    async fn flush_plaintext(&mut self) -> Result<(), Error> {
        if !self.may_send_application_data {
            return Ok(());
        }

        while let Some(buf) = self.sendable_plaintext.pop() {
            self.send_plain(&buf, Limit::No).await?;
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
        self.send_msg(m, self.record_layer.is_encrypting()).await?;
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
        self.send_msg(m, self.record_layer.is_encrypting()).await
    }

    pub(crate) fn set_max_fragment_size(&mut self, new: Option<usize>) -> Result<(), Error> {
        self.message_fragmenter
            .set_max_fragment_size(new)
            .map_err(Error::from)
    }

    pub(crate) fn get_alpn_protocol(&self) -> Option<&[u8]> {
        self.alpn_protocol.as_ref().map(AsRef::as_ref)
    }

    /// Returns true if the caller should call [`Connection::read_tls`] as soon
    /// as possible.
    ///
    /// If there is pending plaintext data to read with [`Connection::reader`],
    /// this returns false.  If your application respects this mechanism,
    /// only one full TLS message will be buffered by rustls.
    pub fn wants_read(&self) -> bool {
        // We want to read more data all the time, except when we have unprocessed plaintext.
        // This provides back-pressure to the TCP buffers. We also don't want to read more after
        // the peer has sent us a close notification.
        //
        // In the handshake case we don't have readable plaintext before the handshake has
        // completed, but also don't want to read if we still have sendable tls.
        self.received_plaintext.is_empty()
            && !self.has_received_close_notify
            && (self.may_send_application_data || self.sendable_tls.is_empty())
    }

    /// Returns true if the peer has sent a close_notify alert.
    pub fn received_close_notify(&self) -> bool {
        self.has_received_close_notify
    }

    /// Returns a reference to the backend.
    pub fn backend(&self) -> &dyn Backend {
        self.backend.as_ref()
    }

    /// Returns a mutable reference to the backend.
    pub fn backend_mut(&mut self) -> &mut dyn Backend {
        self.backend.as_mut()
    }

    fn current_io_state(&self) -> IoState {
        IoState {
            tls_bytes_to_write: self.sendable_tls.len(),
            plaintext_bytes_to_read: self.received_plaintext.len(),
            peer_has_closed: self.has_received_close_notify,
        }
    }
}

#[async_trait]
pub(crate) trait State<ClientConnectionData>: Send + Sync {
    async fn start(
        self: Box<Self>,
        _cx: &mut Context<'_>,
    ) -> Result<Box<dyn State<ClientConnectionData>>, Error> {
        panic!("Start called on unexpected state")
    }

    async fn handle(
        self: Box<Self>,
        cx: &mut Context<'_>,
        message: Message,
    ) -> Result<Box<dyn State<ClientConnectionData>>, Error>;

    fn export_keying_material(
        &self,
        _output: &mut [u8],
        _label: &[u8],
        _context: Option<&[u8]>,
    ) -> Result<(), Error> {
        Err(Error::HandshakeNotComplete)
    }

    async fn perhaps_write_key_update(&mut self, _cx: &mut CommonState) {}
}

pub(crate) struct Context<'a> {
    pub(crate) common: &'a mut CommonState,
    pub(crate) data: &'a mut ClientConnectionData,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Side {
    Client,
}

/// Data specific to the peer's side (client or server).
pub trait SideData {}

const DEFAULT_BUFFER_LIMIT: usize = 64 * 1024;
