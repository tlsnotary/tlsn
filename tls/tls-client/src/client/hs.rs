#[cfg(feature = "logging")]
use crate::bs_debug;
#[cfg(feature = "logging")]
use crate::log::{debug, trace};
use crate::{
    check::inappropriate_handshake_message,
    conn::{CommonState, ConnectionRandoms, State},
    error::Error,
    hash_hs::HandshakeHashBuffer,
    msgs::persist,
    ticketer::TimeBase,
};
use tls_core::{
    key::PublicKey,
    msgs::{
        base::Payload,
        codec::{Codec, Reader},
        enums::{
            AlertDescription, CipherSuite, Compression, ContentType, ECPointFormat, ExtensionType,
            HandshakeType, PSKKeyExchangeMode, ProtocolVersion,
        },
        handshake::{
            CertificateStatusRequest, ClientExtension, ClientHelloPayload, ClientSessionTicket,
            ConvertProtocolNameList, ECPointFormatList, HandshakeMessagePayload, HandshakePayload,
            HasServerExtensions, HelloRetryRequest, ProtocolNameList, Random, SCTList, SessionID,
            SupportedPointFormats,
        },
        message::{Message, MessagePayload},
    },
    suites::SupportedCipherSuite,
};

#[cfg(feature = "tls12")]
use super::tls12;
use crate::client::{
    client_conn::ClientConnectionData, common::ClientHelloDetails, tls13, ClientConfig, ServerName,
};
use async_trait::async_trait;
use std::sync::Arc;

pub(super) type NextState = Box<dyn State<ClientConnectionData>>;
pub(super) type NextStateOrError = Result<NextState, Error>;
pub(super) type ClientContext<'a> = crate::conn::Context<'a>;

fn find_session(
    server_name: &ServerName,
    config: &ClientConfig,
) -> Option<persist::Retrieved<persist::ClientSessionValue>> {
    let key = persist::ClientSessionKey::session_for_server_name(server_name);
    let key_buf = key.get_encoding();

    let value = config.session_storage.get(&key_buf).or_else(|| {
        debug!("No cached session for {:?}", server_name);
        None
    })?;

    #[allow(unused_mut)]
    let mut reader = Reader::init(&value[2..]);
    #[allow(clippy::bind_instead_of_map)] // https://github.com/rust-lang/rust-clippy/issues/8082
    CipherSuite::read_bytes(&value[..2])
        .and_then(|suite| {
            persist::ClientSessionValue::read(&mut reader, suite, &config.cipher_suites)
        })
        .and_then(|resuming| {
            let retrieved = persist::Retrieved::new(resuming, TimeBase::now().ok()?);
            match retrieved.has_expired() {
                false => Some(retrieved),
                true => None,
            }
        })
        .and_then(Some)
}

pub(super) async fn start_handshake(
    server_name: ServerName,
    extra_exts: Vec<ClientExtension>,
    config: Arc<ClientConfig>,
    cx: &mut ClientContext<'_>,
) -> NextStateOrError {
    let mut transcript_buffer = HandshakeHashBuffer::new();
    if config.client_auth_cert_resolver.has_certs() {
        transcript_buffer.set_client_auth_enabled();
    }

    let mut session_id: Option<SessionID> = None;

    let support_tls13 = config.supports_version(ProtocolVersion::TLSv1_3);
    let key_share = if support_tls13 {
        Some(cx.common.backend.get_client_key_share().await?)
    } else {
        None
    };

    // For now we do not support session resumption
    //
    // let mut resuming_session = find_session(&server_name, &config);
    // if let Some(_resuming) = &mut resuming_session {
    //     #[cfg(feature = "tls12")]
    //     if let persist::ClientSessionValue::Tls12(inner) = &mut _resuming.value {
    //         // If we have a ticket, we use the sessionid as a signal that
    //         // we're  doing an abbreviated handshake.  See section 3.4 in
    //         // RFC5077.
    //         if !inner.ticket().is_empty() {
    //             inner.session_id = SessionID::random()?;
    //         }
    //         session_id = Some(inner.session_id);
    //     }

    //     debug!("Resuming session");
    // } else {
    //     debug!("Not resuming any session");
    // }

    // https://tools.ietf.org/html/rfc8446#appendix-D.4
    if session_id.is_none() {
        session_id = Some(SessionID::random()?);
    }

    let random = cx.common.backend.get_client_random().await?;
    let hello_details = ClientHelloDetails::new();
    let sent_tls13_fake_ccs = false;
    let may_send_sct_list = config.verifier.request_scts();
    emit_client_hello_for_retry(
        config,
        cx,
        None,
        random,
        false,
        transcript_buffer,
        sent_tls13_fake_ccs,
        hello_details,
        session_id,
        None,
        server_name,
        key_share,
        extra_exts,
        may_send_sct_list,
        None,
    )
    .await
}

struct ExpectServerHello {
    config: Arc<ClientConfig>,
    resuming_session: Option<persist::Retrieved<persist::ClientSessionValue>>,
    server_name: ServerName,
    random: Random,
    using_ems: bool,
    transcript_buffer: HandshakeHashBuffer,
    hello: ClientHelloDetails,
    offered_key_share: Option<PublicKey>,
    session_id: SessionID,
    sent_tls13_fake_ccs: bool,
    suite: Option<SupportedCipherSuite>,
}

struct ExpectServerHelloOrHelloRetryRequest {
    next: ExpectServerHello,
    extra_exts: Vec<ClientExtension>,
}

async fn emit_client_hello_for_retry(
    config: Arc<ClientConfig>,
    cx: &mut ClientContext<'_>,
    resuming_session: Option<persist::Retrieved<persist::ClientSessionValue>>,
    random: Random,
    using_ems: bool,
    mut transcript_buffer: HandshakeHashBuffer,
    mut sent_tls13_fake_ccs: bool,
    mut hello: ClientHelloDetails,
    session_id: Option<SessionID>,
    retryreq: Option<&HelloRetryRequest>,
    server_name: ServerName,
    key_share: Option<PublicKey>,
    extra_exts: Vec<ClientExtension>,
    may_send_sct_list: bool,
    suite: Option<SupportedCipherSuite>,
) -> Result<NextState, Error> {
    // For now we do not support session resumption
    //
    // Do we have a SessionID or ticket cached for this host?
    // let (ticket, resume_version) = if let Some(resuming) = &resuming_session {
    //     match &resuming.value {
    //         persist::ClientSessionValue::Tls13(inner) => {
    //             (inner.ticket().to_vec(), ProtocolVersion::TLSv1_3)
    //         }
    //         #[cfg(feature = "tls12")]
    //         persist::ClientSessionValue::Tls12(inner) => {
    //             (inner.ticket().to_vec(), ProtocolVersion::TLSv1_2)
    //         }
    //     }
    // } else {
    //     (Vec::new(), ProtocolVersion::Unknown(0))
    // };

    // let (ticket, resume_version) = (Vec::new(), ProtocolVersion::Unknown(0));

    let support_tls12 = config.supports_version(ProtocolVersion::TLSv1_2);
    let support_tls13 = config.supports_version(ProtocolVersion::TLSv1_3);

    let mut supported_versions = Vec::new();
    if support_tls13 {
        supported_versions.push(ProtocolVersion::TLSv1_3);
    }

    if support_tls12 {
        supported_versions.push(ProtocolVersion::TLSv1_2);
    }

    // should be unreachable thanks to config builder
    assert!(!supported_versions.is_empty());

    let mut exts = vec![
        ClientExtension::SupportedVersions(supported_versions),
        ClientExtension::ECPointFormats(ECPointFormatList::supported()),
        ClientExtension::NamedGroups(config.kx_groups.iter().map(|skxg| skxg.name).collect()),
        ClientExtension::SignatureAlgorithms(config.verifier.supported_verify_schemes()),
        //ClientExtension::ExtendedMasterSecretRequest,
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

    if support_tls13 && config.enable_tickets {
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

    // Extra extensions must be placed before the PSK extension
    exts.extend(extra_exts.iter().cloned());

    // let fill_in_binder = if support_tls13
    //     && config.enable_tickets
    //     && resume_version == ProtocolVersion::TLSv1_3
    //     && !ticket.is_empty()
    // {
    //     let resuming =
    //         resuming_session
    //             .as_ref()
    //             .and_then(|resuming| match (suite, resuming.tls13()) {
    //                 (Some(suite), Some(resuming)) => {
    //                     suite.tls13()?.can_resume_from(resuming.suite())?;
    //                     Some(resuming)
    //                 }
    //                 (None, Some(resuming)) => Some(resuming),
    //                 _ => None,
    //             });
    //     if let Some(ref resuming) = resuming {
    //         tls13::prepare_resumption(
    //             &config,
    //             cx,
    //             ticket,
    //             &resuming,
    //             &mut exts,
    //             retryreq.is_some(),
    //         )
    //         .await;
    //     }
    //     resuming
    // } else if config.enable_tickets {
    //     // If we have a ticket, include it.  Otherwise, request one.
    //     if ticket.is_empty() {
    //         exts.push(ClientExtension::SessionTicket(ClientSessionTicket::Request));
    //     } else {
    //         exts.push(ClientExtension::SessionTicket(ClientSessionTicket::Offer(
    //             Payload::new(ticket),
    //         )));
    //     }
    //     None
    // } else {
    //     None
    // };

    // Note what extensions we sent.
    hello.sent_extensions = exts.iter().map(ClientExtension::get_type).collect();

    let session_id = session_id.unwrap_or_else(SessionID::empty);
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

    // let early_key_schedule = if let Some(resuming) = fill_in_binder {
    //     let schedule = tls13::fill_in_psk_binder(&resuming, &transcript_buffer, &mut chp);
    //     Some((resuming.suite(), schedule))
    // } else {
    //     None
    // };

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
        tls13::emit_fake_ccs(&mut sent_tls13_fake_ccs, cx.common).await?;
    }

    trace!("Sending ClientHello {:#?}", ch);

    transcript_buffer.add_message(&ch);
    cx.common.send_msg(ch, false).await?;

    let next = ExpectServerHello {
        config,
        resuming_session,
        server_name,
        random,
        using_ems,
        transcript_buffer,
        hello,
        offered_key_share: key_share,
        session_id,
        sent_tls13_fake_ccs,
        suite,
    };

    if support_tls13 && retryreq.is_none() {
        Ok(Box::new(ExpectServerHelloOrHelloRetryRequest {
            next,
            extra_exts,
        }))
    } else {
        Ok(Box::new(next))
    }
}

pub(super) async fn process_alpn_protocol(
    common: &mut CommonState,
    config: &ClientConfig,
    proto: Option<&[u8]>,
) -> Result<(), Error> {
    common.alpn_protocol = proto.map(ToOwned::to_owned);

    if let Some(alpn_protocol) = &common.alpn_protocol {
        if !config.alpn_protocols.contains(alpn_protocol) {
            return Err(common
                .illegal_param("server sent non-offered ALPN protocol")
                .await?);
        }
    }

    debug!(
        "ALPN protocol is {:?}",
        common.alpn_protocol.as_ref().map(|v| bs_debug::BsDebug(v))
    );
    Ok(())
}

pub(super) fn sct_list_is_invalid(scts: &SCTList) -> bool {
    scts.is_empty() || scts.iter().any(|sct| sct.0.is_empty())
}

#[async_trait]
impl State<ClientConnectionData> for ExpectServerHello {
    async fn handle(
        mut self: Box<Self>,
        cx: &mut ClientContext<'_>,
        m: Message,
    ) -> NextStateOrError {
        let server_hello =
            require_handshake_msg!(m, HandshakeType::ServerHello, HandshakePayload::ServerHello)?;
        trace!("We got ServerHello {:#?}", server_hello);

        use crate::ProtocolVersion::{TLSv1_2, TLSv1_3};
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
                if cx.data.early_data.is_enabled() && cx.common.early_traffic {
                    // The client must fail with a dedicated error code if the server
                    // responds with TLS 1.2 when offering 0-RTT.
                    return Err(Error::PeerMisbehavedError(
                        "server chose v1.2 when offering 0-rtt".to_string(),
                    ));
                }

                if server_hello.get_supported_versions().is_some() {
                    return Err(cx
                        .common
                        .illegal_param("server chose v1.2 using v1.3 extension")
                        .await?);
                }

                TLSv1_2
            }
            _ => {
                cx.common
                    .send_fatal_alert(AlertDescription::ProtocolVersion)
                    .await?;
                let msg = match server_version {
                    TLSv1_2 | TLSv1_3 => "server's TLS version is disabled in client",
                    _ => "server does not support TLS v1.2/v1.3",
                };
                return Err(Error::PeerIncompatibleError(msg.to_string()));
            }
        };

        cx.common.backend.set_protocol_version(version).await?;

        if server_hello.compression_method != Compression::Null {
            return Err(cx
                .common
                .illegal_param("server chose non-Null compression")
                .await?);
        }

        if server_hello.has_duplicate_extension() {
            cx.common
                .send_fatal_alert(AlertDescription::DecodeError)
                .await?;
            return Err(Error::PeerMisbehavedError(
                "server sent duplicate extensions".to_string(),
            ));
        }

        let allowed_unsolicited = [ExtensionType::RenegotiationInfo];
        if self
            .hello
            .server_sent_unsolicited_extensions(&server_hello.extensions, &allowed_unsolicited)
        {
            cx.common
                .send_fatal_alert(AlertDescription::UnsupportedExtension)
                .await?;
            return Err(Error::PeerMisbehavedError(
                "server sent unsolicited extension".to_string(),
            ));
        }

        cx.common.negotiated_version = Some(version);

        // Extract ALPN protocol
        if !cx.common.is_tls13() {
            process_alpn_protocol(cx.common, &self.config, server_hello.get_alpn_protocol())
                .await?;
        }

        // If ECPointFormats extension is supplied by the server, it must contain
        // Uncompressed.  But it's allowed to be omitted.
        if let Some(point_fmts) = server_hello.get_ecpoints_extension() {
            if !point_fmts.contains(&ECPointFormat::Uncompressed) {
                cx.common
                    .send_fatal_alert(AlertDescription::HandshakeFailure)
                    .await?;
                return Err(Error::PeerMisbehavedError(
                    "server does not support uncompressed points".to_string(),
                ));
            }
        }

        let suite = match self.config.find_cipher_suite(server_hello.cipher_suite) {
            Some(suite) => suite,
            None => {
                cx.common
                    .send_fatal_alert(AlertDescription::HandshakeFailure)
                    .await?;
                return Err(Error::PeerMisbehavedError(
                    "server chose non-offered ciphersuite".to_string(),
                ));
            }
        };

        if version != suite.version().version {
            return Err(cx
                .common
                .illegal_param("server chose unusable ciphersuite for version")
                .await?);
        }

        match self.suite {
            Some(prev_suite) if prev_suite != suite => {
                return Err(cx
                    .common
                    .illegal_param("server varied selected ciphersuite")
                    .await?);
            }
            _ => {
                debug!("Using ciphersuite {:?}", suite);
                self.suite = Some(suite);
                cx.common.suite = Some(suite);
                cx.common.backend.set_cipher_suite(suite).await?;
            }
        }

        // Start our handshake hash, and input the server-hello.
        let mut transcript = self.transcript_buffer.start_hash(suite.hash_algorithm());
        transcript.add_message(&m);

        let randoms = ConnectionRandoms::new(self.random, server_hello.random);
        cx.common
            .backend
            .set_server_random(server_hello.random)
            .await?;
        // For TLS1.3, start message encryption using
        // handshake_traffic_secret.
        match suite {
            SupportedCipherSuite::Tls13(suite) => {
                let resuming_session =
                    self.resuming_session
                        .and_then(|resuming| match resuming.value {
                            persist::ClientSessionValue::Tls13(inner) => Some(inner),
                            #[cfg(feature = "tls12")]
                            persist::ClientSessionValue::Tls12(_) => None,
                        });

                tls13::handle_server_hello(
                    self.config,
                    cx,
                    server_hello,
                    resuming_session,
                    self.server_name,
                    randoms,
                    suite,
                    transcript,
                    self.hello,
                    // We always send a key share when TLS 1.3 is enabled.
                    self.offered_key_share.unwrap(),
                    self.sent_tls13_fake_ccs,
                )
                .await
            }
            #[cfg(feature = "tls12")]
            SupportedCipherSuite::Tls12(suite) => {
                let resuming_session =
                    self.resuming_session
                        .and_then(|resuming| match resuming.value {
                            persist::ClientSessionValue::Tls12(inner) => Some(inner),
                            persist::ClientSessionValue::Tls13(_) => None,
                        });

                tls12::CompleteServerHelloHandling {
                    config: self.config,
                    resuming_session,
                    server_name: self.server_name,
                    randoms,
                    using_ems: self.using_ems,
                    transcript,
                }
                .handle_server_hello(cx, suite, server_hello, tls13_supported)
                .await
            }
        }
    }
}

impl ExpectServerHelloOrHelloRetryRequest {
    fn into_expect_server_hello(self) -> NextState {
        Box::new(self.next)
    }

    async fn handle_hello_retry_request(
        self,
        cx: &mut ClientContext<'_>,
        m: Message,
    ) -> NextStateOrError {
        let hrr = require_handshake_msg!(
            m,
            HandshakeType::HelloRetryRequest,
            HandshakePayload::HelloRetryRequest
        )?;
        trace!("Got HRR {:?}", hrr);

        cx.common.check_aligned_handshake().await?;

        let cookie = hrr.get_cookie();
        let req_group = hrr.get_requested_key_share_group();

        // We always send a key share when TLS 1.3 is enabled.
        let offered_key_share = self.next.offered_key_share.unwrap();

        // A retry request is illegal if it contains no cookie and asks for
        // retry of a group we already sent.
        if cookie.is_none() && req_group == Some(offered_key_share.group) {
            return Err(cx
                .common
                .illegal_param("server requested hrr with our group")
                .await?);
        }

        // Or has an empty cookie.
        if let Some(cookie) = cookie {
            if cookie.0.is_empty() {
                return Err(cx
                    .common
                    .illegal_param("server requested hrr with empty cookie")
                    .await?);
            }
        }

        // Or has something unrecognised
        if hrr.has_unknown_extension() {
            cx.common
                .send_fatal_alert(AlertDescription::UnsupportedExtension)
                .await?;
            return Err(Error::PeerIncompatibleError(
                "server sent hrr with unhandled extension".to_string(),
            ));
        }

        // Or has the same extensions more than once
        if hrr.has_duplicate_extension() {
            return Err(cx
                .common
                .illegal_param("server send duplicate hrr extensions")
                .await?);
        }

        // Or asks us to change nothing.
        if cookie.is_none() && req_group.is_none() {
            return Err(cx
                .common
                .illegal_param("server requested hrr with no changes")
                .await?);
        }

        // Or asks us to talk a protocol we didn't offer, or doesn't support HRR at all.
        match hrr.get_supported_versions() {
            Some(ProtocolVersion::TLSv1_3) => {
                cx.common.negotiated_version = Some(ProtocolVersion::TLSv1_3);
            }
            _ => {
                return Err(cx
                    .common
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
                    .common
                    .illegal_param("server requested unsupported cs in hrr")
                    .await?);
            }
        };

        // HRR selects the ciphersuite.
        cx.common.suite = Some(cs);

        // This is the draft19 change where the transcript became a tree
        let transcript = self.next.transcript_buffer.start_hash(cs.hash_algorithm());
        let mut transcript_buffer = transcript.into_hrr_buffer();
        transcript_buffer.add_message(&m);

        // Early data is not allowed after HelloRetryrequest
        if cx.data.early_data.is_enabled() {
            cx.data.early_data.rejected();
        }

        let may_send_sct_list = self.next.hello.server_may_send_sct_list();

        let key_share = match req_group {
            Some(group) if group != offered_key_share.group => {
                // For now we do not support changing group after starting hs
                return Err(cx
                    .common
                    .illegal_param("server requested hrr with bad group")
                    .await?);
            }
            _ => offered_key_share,
        };

        emit_client_hello_for_retry(
            self.next.config,
            cx,
            self.next.resuming_session,
            self.next.random,
            self.next.using_ems,
            transcript_buffer,
            self.next.sent_tls13_fake_ccs,
            self.next.hello,
            Some(self.next.session_id),
            Some(hrr),
            self.next.server_name,
            Some(key_share),
            self.extra_exts,
            may_send_sct_list,
            Some(cs),
        )
        .await
    }
}

#[async_trait]
impl State<ClientConnectionData> for ExpectServerHelloOrHelloRetryRequest {
    async fn handle(self: Box<Self>, cx: &mut ClientContext<'_>, m: Message) -> NextStateOrError {
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

pub(super) async fn send_cert_error_alert(
    common: &mut CommonState,
    err: Error,
) -> Result<Error, Error> {
    match err {
        Error::InvalidCertificateEncoding => {
            common
                .send_fatal_alert(AlertDescription::DecodeError)
                .await?;
        }
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
