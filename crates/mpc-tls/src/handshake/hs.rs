use crate::{
    conn::{Conn, ConnectionRandoms},
    handshake::{
        ClientConfig, ResolvesClientCert, ServerName, check::inappropriate_handshake_message,
        error::Error, hash_hs::HandshakeHashBuffer, sign, tls12, tls13,
    },
};
use std::sync::Arc;
use tls_core::{
    key::PublicKey,
    msgs::{
        enums::{
            AlertDescription, CipherSuite, Compression, ContentType, ECPointFormat, ExtensionType,
            HandshakeType, NamedGroup, PSKKeyExchangeMode, ProtocolVersion, SignatureScheme,
        },
        handshake::{
            CertificateStatusRequest, ClientExtension, ClientHelloPayload, ConvertProtocolNameList,
            DistinguishedNames, ECPointFormatList, HandshakeMessagePayload, HandshakePayload,
            HasServerExtensions, HelloRetryRequest, ProtocolNameList, Random, SCTList,
            ServerExtension, SessionID, SupportedPointFormats,
        },
        message::{Message, MessagePayload},
    },
    suites::SupportedCipherSuite,
};
use tracing::{debug, trace};

pub(crate) use tls_core::cert::ServerCertDetails;

/// The TLS handshake state machine.
///
/// This replaces the boxed-trait-object state machine of upstream rustls with a
/// closed enum. Each variant carries the typed state for one step of the
/// handshake; [`Handshake::handle`] dispatches an incoming TLS message to the
/// current state, which returns the next state. Handlers operate directly on
/// the live connection ([`Live`]), reaching both the TLS framing state and the
/// MPC session through its inherent methods.
pub(crate) enum Handshake {
    ExpectServerHello(Box<ExpectServerHello>),
    ExpectServerHelloOrHelloRetryRequest(Box<ExpectServerHelloOrHelloRetryRequest>),
    Tls12ExpectCertificate(Box<tls12::ExpectCertificate>),
    Tls12ExpectCertificateStatusOrServerKx(Box<tls12::ExpectCertificateStatusOrServerKx>),
    Tls12ExpectServerKx(Box<tls12::ExpectServerKx>),
    Tls12ExpectServerDoneOrCertReq(Box<tls12::ExpectServerDoneOrCertReq>),
    Tls12ExpectServerDone(Box<tls12::ExpectServerDone>),
    Tls12ExpectCcs(Box<tls12::ExpectCcs>),
    Tls12ExpectFinished(Box<tls12::ExpectFinished>),
    Tls13ExpectEncryptedExtensions(Box<tls13::ExpectEncryptedExtensions>),
    Tls13ExpectCertificateOrCertReq(Box<tls13::ExpectCertificateOrCertReq>),
    Tls13ExpectCertificate(Box<tls13::ExpectCertificate>),
    Tls13ExpectCertificateVerify(Box<tls13::ExpectCertificateVerify>),
    Tls13ExpectFinished(Box<tls13::ExpectFinished>),
    /// Terminal signal: the handshake is complete. The connection driver
    /// transitions to the online phase on seeing this; it is never dispatched a
    /// message.
    Complete,
}

impl Handshake {
    /// Dispatches an incoming TLS message to the current handshake state,
    /// returning the next state.
    pub(crate) async fn handle(self, cx: &mut Conn, m: Message) -> Result<Handshake, Error> {
        match self {
            Handshake::ExpectServerHello(s) => s.handle(cx, m).await,
            Handshake::ExpectServerHelloOrHelloRetryRequest(s) => s.handle(cx, m).await,
            Handshake::Tls12ExpectCertificate(s) => s.handle(cx, m).await,
            Handshake::Tls12ExpectCertificateStatusOrServerKx(s) => s.handle(cx, m).await,
            Handshake::Tls12ExpectServerKx(s) => s.handle(cx, m).await,
            Handshake::Tls12ExpectServerDoneOrCertReq(s) => s.handle(cx, m).await,
            Handshake::Tls12ExpectServerDone(s) => s.handle(cx, m).await,
            Handshake::Tls12ExpectCcs(s) => s.handle(cx, m).await,
            Handshake::Tls12ExpectFinished(s) => s.handle(cx, m).await,
            Handshake::Tls13ExpectEncryptedExtensions(s) => s.handle(cx, m).await,
            Handshake::Tls13ExpectCertificateOrCertReq(s) => s.handle(cx, m).await,
            Handshake::Tls13ExpectCertificate(s) => s.handle(cx, m).await,
            Handshake::Tls13ExpectCertificateVerify(s) => s.handle(cx, m).await,
            Handshake::Tls13ExpectFinished(s) => s.handle(cx, m).await,
            Handshake::Complete => Err(Error::General(
                "handshake state machine stepped after completion".to_string(),
            )),
        }
    }
}

/// The next handshake state.
pub(crate) type NextState = Handshake;
/// The next handshake state, or a fatal error.
pub(crate) type NextStateOrError = Result<Handshake, Error>;

pub(crate) async fn start_handshake(
    server_name: ServerName,
    config: Arc<ClientConfig>,
    cx: &mut Conn,
) -> NextStateOrError {
    let mut transcript_buffer = HandshakeHashBuffer::new();
    if config.client_auth_cert_resolver.has_certs() {
        transcript_buffer.set_client_auth_enabled();
    }

    // Session resumption is not supported: the master secret is secret-shared
    // inside the MPC backend, so there is nothing the client could store.
    // A random session id is sent for middlebox compatibility.
    // https://tools.ietf.org/html/rfc8446#appendix-D.4
    let session_id = SessionID::random()?;

    let support_tls13 = config.supports_version(ProtocolVersion::TLSv1_3);
    let key_share = if support_tls13 {
        Some(cx.client_key_share()?)
    } else {
        None
    };

    let random = cx.client_random;
    let hello_details = ClientHelloDetails::new();
    let sent_tls13_fake_ccs = false;
    let may_send_sct_list = config.verifier.request_scts();
    emit_client_hello_for_retry(
        config,
        cx,
        random,
        transcript_buffer,
        sent_tls13_fake_ccs,
        hello_details,
        session_id,
        None,
        server_name,
        key_share,
        may_send_sct_list,
        None,
    )
    .await
}

pub(crate) struct ExpectServerHello {
    config: Arc<ClientConfig>,
    server_name: ServerName,
    random: Random,
    transcript_buffer: HandshakeHashBuffer,
    hello: ClientHelloDetails,
    offered_key_share: Option<PublicKey>,
    session_id: SessionID,
    sent_tls13_fake_ccs: bool,
    suite: Option<SupportedCipherSuite>,
}

pub(crate) struct ExpectServerHelloOrHelloRetryRequest {
    next: ExpectServerHello,
}

#[allow(clippy::too_many_arguments)]
async fn emit_client_hello_for_retry(
    config: Arc<ClientConfig>,
    cx: &mut Conn,
    random: Random,
    mut transcript_buffer: HandshakeHashBuffer,
    mut sent_tls13_fake_ccs: bool,
    mut hello: ClientHelloDetails,
    session_id: SessionID,
    retryreq: Option<&HelloRetryRequest>,
    server_name: ServerName,
    key_share: Option<PublicKey>,
    may_send_sct_list: bool,
    suite: Option<SupportedCipherSuite>,
) -> Result<NextState, Error> {
    let support_tls12 = config.supports_version(ProtocolVersion::TLSv1_2);
    let support_tls13 = config.supports_version(ProtocolVersion::TLSv1_3);

    let mut supported_versions = Vec::new();
    if support_tls13 {
        supported_versions.push(ProtocolVersion::TLSv1_3);
    }

    if support_tls12 {
        supported_versions.push(ProtocolVersion::TLSv1_2);
    }

    // Unreachable: the versions are fixed in `ClientConfig::new`.
    assert!(!supported_versions.is_empty());

    let mut exts = vec![
        ClientExtension::SupportedVersions(supported_versions),
        ClientExtension::ECPointFormats(ECPointFormatList::supported()),
        // The MPC backend only supports P-256.
        ClientExtension::NamedGroups(vec![NamedGroup::secp256r1]),
        ClientExtension::SignatureAlgorithms(config.verifier.supported_verify_schemes()),
        // The extended master secret extension is not supported by the MPC
        // backend.
        ClientExtension::CertificateStatusRequest(CertificateStatusRequest::build_ocsp()),
    ];

    if let (Some(sni_name), true) = (server_name.for_sni(), config.enable_sni) {
        exts.push(ClientExtension::make_sni(sni_name));
    }

    if may_send_sct_list {
        exts.push(ClientExtension::SignedCertificateTimestampRequest);
    }

    if let Some(key_share) = &key_share {
        debug_assert!(support_tls13);
        exts.push(ClientExtension::KeyShare(vec![key_share.clone().into()]));
    }

    if let Some(cookie) = retryreq.and_then(HelloRetryRequest::get_cookie) {
        exts.push(ClientExtension::Cookie(cookie.clone()));
    }

    if support_tls13 {
        // We could support PSK_KE here too. Such connections don't
        // have forward secrecy, and are similar to TLS1.2 resumption.
        let psk_modes = vec![PSKKeyExchangeMode::PSK_DHE_KE];
        exts.push(ClientExtension::PresharedKeyModes(psk_modes));
    }

    if !config.alpn_protocols.is_empty() {
        exts.push(ClientExtension::Protocols(ProtocolNameList::from_slices(
            &config
                .alpn_protocols
                .iter()
                .map(|proto| &proto[..])
                .collect::<Vec<_>>(),
        )));
    }

    // Note what extensions we sent.
    hello.sent_extensions = exts.iter().map(ClientExtension::get_type).collect();

    let mut cipher_suites: Vec<_> = config.cipher_suites.iter().map(|cs| cs.suite()).collect();
    // We don't do renegotiation at all, in fact.
    cipher_suites.push(CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV);

    let chp = HandshakeMessagePayload {
        typ: HandshakeType::ClientHello,
        payload: HandshakePayload::ClientHello(ClientHelloPayload {
            client_version: ProtocolVersion::TLSv1_2,
            random,
            session_id,
            cipher_suites,
            compression_methods: vec![Compression::Null],
            extensions: exts,
        }),
    };

    let ch = Message {
        // "This value MUST be set to 0x0303 for all records generated
        //  by a TLS 1.3 implementation other than an initial ClientHello
        //  (i.e., one not generated after a HelloRetryRequest)"
        version: if retryreq.is_some() {
            ProtocolVersion::TLSv1_2
        } else {
            ProtocolVersion::TLSv1_0
        },
        payload: MessagePayload::Handshake(chp),
    };

    if retryreq.is_some() {
        // send dummy CCS to fool middleboxes prior
        // to second client hello
        tls13::emit_fake_ccs(&mut sent_tls13_fake_ccs, cx).await?;
    }

    trace!("Sending ClientHello {:#?}", ch);

    transcript_buffer.add_message(&ch);
    cx.send_msg(ch, false).await?;

    let next = ExpectServerHello {
        config,
        server_name,
        random,
        transcript_buffer,
        hello,
        offered_key_share: key_share,
        session_id,
        sent_tls13_fake_ccs,
        suite,
    };

    if support_tls13 && retryreq.is_none() {
        Ok(Handshake::ExpectServerHelloOrHelloRetryRequest(Box::new(
            ExpectServerHelloOrHelloRetryRequest { next },
        )))
    } else {
        Ok(Handshake::ExpectServerHello(Box::new(next)))
    }
}

pub(crate) async fn process_alpn_protocol(
    common: &mut Conn,
    config: &ClientConfig,
    proto: Option<&[u8]>,
) -> Result<(), Error> {
    common.io.alpn_protocol = proto.map(ToOwned::to_owned);

    if let Some(alpn_protocol) = &common.io.alpn_protocol
        && !config.alpn_protocols.contains(alpn_protocol)
    {
        return Err(common
            .illegal_param("server sent non-offered ALPN protocol")
            .await?);
    }

    debug!(
        "ALPN protocol is {:?}",
        common
            .io
            .alpn_protocol
            .as_ref()
            .map(|v| String::from_utf8_lossy(v))
    );
    Ok(())
}

pub(crate) fn sct_list_is_invalid(scts: &SCTList) -> bool {
    scts.is_empty() || scts.iter().any(|sct| sct.0.is_empty())
}

impl ExpectServerHello {
    pub(crate) async fn handle(mut self: Box<Self>, cx: &mut Conn, m: Message) -> NextStateOrError {
        let server_hello =
            require_handshake_msg!(m, HandshakeType::ServerHello, HandshakePayload::ServerHello)?;
        trace!("We got ServerHello {:#?}", server_hello);

        use tls_core::msgs::enums::ProtocolVersion::{TLSv1_2, TLSv1_3};
        let tls13_supported = self.config.supports_version(TLSv1_3);

        let server_version = if server_hello.legacy_version == TLSv1_2 {
            server_hello
                .get_supported_versions()
                .unwrap_or(server_hello.legacy_version)
        } else {
            server_hello.legacy_version
        };

        let version = match server_version {
            TLSv1_3 if tls13_supported => TLSv1_3,
            TLSv1_2 if self.config.supports_version(TLSv1_2) => {
                if server_hello.get_supported_versions().is_some() {
                    return Err(cx
                        .illegal_param("server chose v1.2 using v1.3 extension")
                        .await?);
                }

                TLSv1_2
            }
            _ => {
                cx.send_fatal_alert(AlertDescription::ProtocolVersion)
                    .await?;
                let msg = match server_version {
                    TLSv1_2 | TLSv1_3 => "server's TLS version is disabled in client",
                    _ => "server does not support TLS v1.2/v1.3",
                };
                return Err(Error::PeerIncompatibleError(msg.to_string()));
            }
        };

        if server_hello.compression_method != Compression::Null {
            return Err(cx
                .illegal_param("server chose non-Null compression")
                .await?);
        }

        if server_hello.has_duplicate_extension() {
            cx.send_fatal_alert(AlertDescription::DecodeError).await?;
            return Err(Error::PeerMisbehavedError(
                "server sent duplicate extensions".to_string(),
            ));
        }

        let allowed_unsolicited = [ExtensionType::RenegotiationInfo];
        if self
            .hello
            .server_sent_unsolicited_extensions(&server_hello.extensions, &allowed_unsolicited)
        {
            cx.send_fatal_alert(AlertDescription::UnsupportedExtension)
                .await?;
            return Err(Error::PeerMisbehavedError(
                "server sent unsolicited extension".to_string(),
            ));
        }

        cx.io.negotiated_version = Some(version);

        // Extract ALPN protocol
        if !cx.io.is_tls13() {
            process_alpn_protocol(cx, &self.config, server_hello.get_alpn_protocol()).await?;
        }

        // If ECPointFormats extension is supplied by the server, it must contain
        // Uncompressed.  But it's allowed to be omitted.
        if let Some(point_fmts) = server_hello.get_ecpoints_extension()
            && !point_fmts.contains(&ECPointFormat::Uncompressed)
        {
            cx.send_fatal_alert(AlertDescription::HandshakeFailure)
                .await?;
            return Err(Error::PeerMisbehavedError(
                "server does not support uncompressed points".to_string(),
            ));
        }

        let suite = match self.config.find_cipher_suite(server_hello.cipher_suite) {
            Some(suite) => suite,
            None => {
                cx.send_fatal_alert(AlertDescription::HandshakeFailure)
                    .await?;
                return Err(Error::PeerMisbehavedError(
                    "server chose non-offered ciphersuite".to_string(),
                ));
            }
        };

        if version != suite.version().version {
            return Err(cx
                .illegal_param("server chose unusable ciphersuite for version")
                .await?);
        }

        match self.suite {
            Some(prev_suite) if prev_suite != suite => {
                return Err(cx
                    .illegal_param("server varied selected ciphersuite")
                    .await?);
            }
            _ => {
                debug!("Using ciphersuite {:?}", suite);
                self.suite = Some(suite);
                cx.io.suite = Some(suite);
            }
        }

        // Start our handshake hash, and input the server-hello.
        let mut transcript = self.transcript_buffer.start_hash(suite.hash_algorithm());
        transcript.add_message(&m);

        let randoms = ConnectionRandoms::new(self.random, server_hello.random);
        // For TLS1.3, start message encryption using
        // handshake_traffic_secret.
        match suite {
            SupportedCipherSuite::Tls13(_) => {
                tls13::handle_server_hello(
                    self.config,
                    cx,
                    server_hello,
                    self.server_name,
                    transcript,
                    self.hello,
                    // We always send a key share when TLS 1.3 is enabled.
                    self.offered_key_share.unwrap(),
                    self.sent_tls13_fake_ccs,
                )
                .await
            }
            SupportedCipherSuite::Tls12(suite) => {
                tls12::CompleteServerHelloHandling {
                    config: self.config,
                    server_name: self.server_name,
                    randoms,
                    transcript,
                }
                .handle_server_hello(cx, suite, server_hello, tls13_supported)
                .await
            }
        }
    }
}

impl ExpectServerHelloOrHelloRetryRequest {
    fn into_expect_server_hello(self) -> Box<ExpectServerHello> {
        Box::new(self.next)
    }

    async fn handle_hello_retry_request(self, cx: &mut Conn, m: Message) -> NextStateOrError {
        let hrr = require_handshake_msg!(
            m,
            HandshakeType::HelloRetryRequest,
            HandshakePayload::HelloRetryRequest
        )?;
        trace!("Got HRR {:?}", hrr);

        cx.check_aligned_handshake().await?;

        let cookie = hrr.get_cookie();
        let req_group = hrr.get_requested_key_share_group();

        // We always send a key share when TLS 1.3 is enabled.
        let offered_key_share = self.next.offered_key_share.unwrap();

        // A retry request is illegal if it contains no cookie and asks for
        // retry of a group we already sent.
        if cookie.is_none() && req_group == Some(offered_key_share.group) {
            return Err(cx
                .illegal_param("server requested hrr with our group")
                .await?);
        }

        // Or has an empty cookie.
        if let Some(cookie) = cookie
            && cookie.0.is_empty()
        {
            return Err(cx
                .illegal_param("server requested hrr with empty cookie")
                .await?);
        }

        // Or has something unrecognised
        if hrr.has_unknown_extension() {
            cx.send_fatal_alert(AlertDescription::UnsupportedExtension)
                .await?;
            return Err(Error::PeerIncompatibleError(
                "server sent hrr with unhandled extension".to_string(),
            ));
        }

        // Or has the same extensions more than once
        if hrr.has_duplicate_extension() {
            return Err(cx
                .illegal_param("server send duplicate hrr extensions")
                .await?);
        }

        // Or asks us to change nothing.
        if cookie.is_none() && req_group.is_none() {
            return Err(cx
                .illegal_param("server requested hrr with no changes")
                .await?);
        }

        // Or asks us to talk a protocol we didn't offer, or doesn't support HRR at all.
        match hrr.get_supported_versions() {
            Some(ProtocolVersion::TLSv1_3) => {
                cx.io.negotiated_version = Some(ProtocolVersion::TLSv1_3);
            }
            _ => {
                return Err(cx
                    .illegal_param("server requested unsupported version in hrr")
                    .await?);
            }
        }

        // Or asks us to use a ciphersuite we didn't offer.
        let maybe_cs = self.next.config.find_cipher_suite(hrr.cipher_suite);
        let cs = match maybe_cs {
            Some(cs) => cs,
            None => {
                return Err(cx
                    .illegal_param("server requested unsupported cs in hrr")
                    .await?);
            }
        };

        // HRR selects the ciphersuite.
        cx.io.suite = Some(cs);

        // This is the draft19 change where the transcript became a tree
        let transcript = self.next.transcript_buffer.start_hash(cs.hash_algorithm());
        let mut transcript_buffer = transcript.into_hrr_buffer();
        transcript_buffer.add_message(&m);

        let may_send_sct_list = self.next.hello.server_may_send_sct_list();

        let key_share = match req_group {
            Some(group) if group != offered_key_share.group => {
                // For now we do not support changing group after starting hs
                return Err(cx
                    .illegal_param("server requested hrr with bad group")
                    .await?);
            }
            _ => offered_key_share,
        };

        emit_client_hello_for_retry(
            self.next.config,
            cx,
            self.next.random,
            transcript_buffer,
            self.next.sent_tls13_fake_ccs,
            self.next.hello,
            self.next.session_id,
            Some(hrr),
            self.next.server_name,
            Some(key_share),
            may_send_sct_list,
            Some(cs),
        )
        .await
    }

    pub(crate) async fn handle(self: Box<Self>, cx: &mut Conn, m: Message) -> NextStateOrError {
        match m.payload {
            MessagePayload::Handshake(HandshakeMessagePayload {
                payload: HandshakePayload::ServerHello(..),
                ..
            }) => self.into_expect_server_hello().handle(cx, m).await,
            MessagePayload::Handshake(HandshakeMessagePayload {
                payload: HandshakePayload::HelloRetryRequest(..),
                ..
            }) => self.handle_hello_retry_request(cx, m).await,
            payload => Err(inappropriate_handshake_message(
                &payload,
                &[ContentType::Handshake],
                &[HandshakeType::ServerHello, HandshakeType::HelloRetryRequest],
            )),
        }
    }
}

pub(crate) async fn send_cert_error_alert(common: &mut Conn, err: Error) -> Result<Error, Error> {
    match err {
        Error::PeerMisbehavedError(_) => {
            common
                .send_fatal_alert(AlertDescription::IllegalParameter)
                .await?;
        }
        _ => {
            common
                .send_fatal_alert(AlertDescription::BadCertificate)
                .await?;
        }
    };

    Ok(err)
}

// --- Handshake details (formerly common.rs) ---

pub(crate) struct ClientHelloDetails {
    pub(crate) sent_extensions: Vec<ExtensionType>,
}

impl ClientHelloDetails {
    pub(crate) fn new() -> Self {
        Self {
            sent_extensions: Vec::new(),
        }
    }

    pub(crate) fn server_may_send_sct_list(&self) -> bool {
        self.sent_extensions.contains(&ExtensionType::SCT)
    }

    pub(crate) fn server_sent_unsolicited_extensions(
        &self,
        received_exts: &[ServerExtension],
        allowed_unsolicited: &[ExtensionType],
    ) -> bool {
        for ext in received_exts {
            let ext_type = ext.get_type();
            if !self.sent_extensions.contains(&ext_type) && !allowed_unsolicited.contains(&ext_type)
            {
                trace!("Unsolicited extension {:?}", ext_type);
                return true;
            }
        }

        false
    }
}

pub(crate) enum ClientAuthDetails {
    /// Send an empty `Certificate` and no `CertificateVerify`.
    Empty { auth_context_tls13: Option<Vec<u8>> },
    /// Send a non-empty `Certificate` and a `CertificateVerify`.
    Verify {
        certkey: Arc<sign::CertifiedKey>,
        signer: Box<dyn sign::Signer>,
        auth_context_tls13: Option<Vec<u8>>,
    },
}

impl ClientAuthDetails {
    pub(crate) fn resolve(
        resolver: &dyn ResolvesClientCert,
        canames: Option<&DistinguishedNames>,
        sigschemes: &[SignatureScheme],
        auth_context_tls13: Option<Vec<u8>>,
    ) -> Self {
        let acceptable_issuers = canames
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .map(|p| p.0.as_slice())
            .collect::<Vec<&[u8]>>();

        if let Some(certkey) = resolver.resolve(&acceptable_issuers, sigschemes)
            && let Some(signer) = certkey.key.choose_scheme(sigschemes)
        {
            debug!("Attempting client auth");
            return Self::Verify {
                certkey,
                signer,
                auth_context_tls13,
            };
        }

        debug!("Client auth requested but no cert/sigscheme available");
        Self::Empty { auth_context_tls13 }
    }
}
