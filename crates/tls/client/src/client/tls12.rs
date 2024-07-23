use super::{client_conn::ClientConnectionData, hs::ClientContext};
#[cfg(feature = "logging")]
use crate::log::{debug, trace};
use crate::{
    check::{inappropriate_handshake_message, inappropriate_message},
    client::{
        common::{ClientAuthDetails, ServerCertDetails},
        hs, ClientConfig, ServerName,
    },
    conn::{CommonState, ConnectionRandoms, State},
    error::Error,
    hash_hs::HandshakeHash,
    msgs::persist,
    sign::Signer,
    ticketer::TimeBase,
    verify,
};
use async_trait::async_trait;
use ring::constant_time;
use std::sync::Arc;
use tls_core::{
    ke::ServerKxDetails,
    key::PublicKey,
    msgs::{
        base::{Payload, PayloadU8},
        ccs::ChangeCipherSpecPayload,
        codec::Codec,
        enums::{AlertDescription, ContentType, HandshakeType, ProtocolVersion},
        handshake::{
            CertificatePayload, DecomposedSignatureScheme, DigitallySignedStruct,
            HandshakeMessagePayload, HandshakePayload, NewSessionTicketPayload, SCTList,
            ServerECDHParams, SessionID,
        },
        message::{Message, MessagePayload},
    },
    suites::{tls12, SupportedCipherSuite, Tls12CipherSuite},
};

pub(super) use server_hello::CompleteServerHelloHandling;

mod server_hello {
    use tls_core::msgs::{
        enums::ExtensionType,
        handshake::{HasServerExtensions, ServerHelloPayload},
    };

    use super::*;

    pub(in crate::client) struct CompleteServerHelloHandling {
        pub(in crate::client) config: Arc<ClientConfig>,
        pub(in crate::client) resuming_session: Option<persist::Tls12ClientSessionValue>,
        pub(in crate::client) server_name: ServerName,
        pub(in crate::client) randoms: ConnectionRandoms,
        pub(in crate::client) using_ems: bool,
        pub(in crate::client) transcript: HandshakeHash,
    }

    impl CompleteServerHelloHandling {
        pub(in crate::client) async fn handle_server_hello(
            mut self,
            cx: &mut ClientContext<'_>,
            suite: &'static Tls12CipherSuite,
            server_hello: &ServerHelloPayload,
            tls13_supported: bool,
        ) -> hs::NextStateOrError {
            server_hello.random.write_slice(&mut self.randoms.server);

            // Look for TLS1.3 downgrade signal in server random
            // both the server random and TLS12_DOWNGRADE_SENTINEL are
            // public values and don't require constant time comparison
            let has_downgrade_marker = self.randoms.server[24..] == tls12::DOWNGRADE_SENTINEL;
            if tls13_supported && has_downgrade_marker {
                return Err(cx
                    .common
                    .illegal_param("downgrade to TLS1.2 when TLS1.3 is supported")
                    .await?);
            }

            // Doing EMS?
            self.using_ems = server_hello.ems_support_acked();

            // Might the server send a ticket?
            let must_issue_new_ticket = if server_hello
                .find_extension(ExtensionType::SessionTicket)
                .is_some()
            {
                debug!("Server supports tickets");
                true
            } else {
                false
            };

            // Might the server send a CertificateStatus between Certificate and
            // ServerKeyExchange?
            let may_send_cert_status = server_hello
                .find_extension(ExtensionType::StatusRequest)
                .is_some();
            if may_send_cert_status {
                debug!("Server may staple OCSP response");
            }

            // Save any sent SCTs for verification against the certificate.
            let server_cert_sct_list = if let Some(sct_list) = server_hello.get_sct_list() {
                debug!("Server sent {:?} SCTs", sct_list.len());

                if hs::sct_list_is_invalid(sct_list) {
                    let error_msg = "server sent invalid SCT list".to_string();
                    return Err(Error::PeerMisbehavedError(error_msg));
                }
                Some(sct_list.clone())
            } else {
                None
            };

            // See if we're successfully resuming.
            if let Some(ref _resuming) = self.resuming_session {
                return Err(Error::General(
                    "client does not support resumption".to_string(),
                ));
                // if resuming.session_id == server_hello.session_id {
                //     debug!("Server agreed to resume");

                //     // Is the server telling lies about the ciphersuite?
                //     if resuming.suite() != suite {
                //         let error_msg =
                //             "abbreviated handshake offered, but with varied cs".to_string();
                //         return Err(Error::PeerMisbehavedError(error_msg));
                //     }

                //     // And about EMS support?
                //     if resuming.extended_ms() != self.using_ems {
                //         let error_msg = "server varied ems support over resume".to_string();
                //         return Err(Error::PeerMisbehavedError(error_msg));
                //     }

                //     let secrets =
                //         ConnectionSecrets::new_resume(self.randoms, suite, resuming.secret());
                //     self.config.key_log.log(
                //         "CLIENT_RANDOM",
                //         &secrets.randoms.client,
                //         &secrets.master_secret,
                //     );
                //     cx.common.start_encryption_tls12(&secrets, Side::Client);

                //     // Since we're resuming, we verified the certificate and
                //     // proof of possession in the prior session.
                //     cx.common.peer_certificates = Some(resuming.server_cert_chain().to_vec());
                //     let cert_verified = verify::ServerCertVerified::assertion();
                //     let sig_verified = verify::HandshakeSignatureValid::assertion();

                //     return if must_issue_new_ticket {
                //         Ok(Box::new(ExpectNewTicket {
                //             config: self.config,
                //             secrets,
                //             resuming_session: self.resuming_session,
                //             session_id: server_hello.session_id,
                //             server_name: self.server_name,
                //             using_ems: self.using_ems,
                //             transcript: self.transcript,
                //             resuming: true,
                //             cert_verified,
                //             sig_verified,
                //         }))
                //     } else {
                //         Ok(Box::new(ExpectCcs {
                //             config: self.config,
                //             secrets,
                //             resuming_session: self.resuming_session,
                //             session_id: server_hello.session_id,
                //             server_name: self.server_name,
                //             using_ems: self.using_ems,
                //             transcript: self.transcript,
                //             ticket: None,
                //             resuming: true,
                //             cert_verified,
                //             sig_verified,
                //         }))
                //     };
                // }
            }

            Ok(Box::new(ExpectCertificate {
                config: self.config,
                resuming_session: self.resuming_session,
                session_id: server_hello.session_id,
                server_name: self.server_name,
                randoms: self.randoms,
                using_ems: self.using_ems,
                transcript: self.transcript,
                suite,
                may_send_cert_status,
                must_issue_new_ticket,
                server_cert_sct_list,
            }))
        }
    }
}

struct ExpectCertificate {
    config: Arc<ClientConfig>,
    resuming_session: Option<persist::Tls12ClientSessionValue>,
    session_id: SessionID,
    server_name: ServerName,
    randoms: ConnectionRandoms,
    using_ems: bool,
    transcript: HandshakeHash,
    pub(super) suite: &'static Tls12CipherSuite,
    may_send_cert_status: bool,
    must_issue_new_ticket: bool,
    server_cert_sct_list: Option<SCTList>,
}

#[async_trait]
impl State<ClientConnectionData> for ExpectCertificate {
    async fn handle(
        mut self: Box<Self>,
        cx: &mut ClientContext<'_>,
        m: Message,
    ) -> hs::NextStateOrError {
        self.transcript.add_message(&m);
        let server_cert_chain = require_handshake_msg_move!(
            m,
            HandshakeType::Certificate,
            HandshakePayload::Certificate
        )?;

        if self.may_send_cert_status {
            Ok(Box::new(ExpectCertificateStatusOrServerKx {
                config: self.config,
                resuming_session: self.resuming_session,
                session_id: self.session_id,
                server_name: self.server_name,
                randoms: self.randoms,
                using_ems: self.using_ems,
                transcript: self.transcript,
                suite: self.suite,
                server_cert_sct_list: self.server_cert_sct_list,
                server_cert_chain,
                must_issue_new_ticket: self.must_issue_new_ticket,
            }))
        } else {
            let server_cert =
                ServerCertDetails::new(server_cert_chain, vec![], self.server_cert_sct_list);

            cx.common
                .backend
                .set_server_cert_details(server_cert.clone())
                .await?;

            Ok(Box::new(ExpectServerKx {
                config: self.config,
                resuming_session: self.resuming_session,
                session_id: self.session_id,
                server_name: self.server_name,
                randoms: self.randoms,
                using_ems: self.using_ems,
                transcript: self.transcript,
                suite: self.suite,
                server_cert,
                must_issue_new_ticket: self.must_issue_new_ticket,
            }))
        }
    }
}

struct ExpectCertificateStatusOrServerKx {
    config: Arc<ClientConfig>,
    resuming_session: Option<persist::Tls12ClientSessionValue>,
    session_id: SessionID,
    server_name: ServerName,
    randoms: ConnectionRandoms,
    using_ems: bool,
    transcript: HandshakeHash,
    suite: &'static Tls12CipherSuite,
    server_cert_sct_list: Option<SCTList>,
    server_cert_chain: CertificatePayload,
    must_issue_new_ticket: bool,
}

#[async_trait]
impl State<ClientConnectionData> for ExpectCertificateStatusOrServerKx {
    async fn handle(
        self: Box<Self>,
        cx: &mut ClientContext<'_>,
        m: Message,
    ) -> hs::NextStateOrError {
        match m.payload {
            MessagePayload::Handshake(HandshakeMessagePayload {
                payload: HandshakePayload::ServerKeyExchange(..),
                ..
            }) => {
                let server_cert_details = ServerCertDetails::new(
                    self.server_cert_chain,
                    vec![],
                    self.server_cert_sct_list,
                );

                cx.common
                    .backend
                    .set_server_cert_details(server_cert_details.clone())
                    .await?;

                Box::new(ExpectServerKx {
                    config: self.config,
                    resuming_session: self.resuming_session,
                    session_id: self.session_id,
                    server_name: self.server_name,
                    randoms: self.randoms,
                    using_ems: self.using_ems,
                    transcript: self.transcript,
                    suite: self.suite,
                    server_cert: server_cert_details,
                    must_issue_new_ticket: self.must_issue_new_ticket,
                })
                .handle(cx, m)
                .await
            }
            MessagePayload::Handshake(HandshakeMessagePayload {
                payload: HandshakePayload::CertificateStatus(..),
                ..
            }) => {
                Box::new(ExpectCertificateStatus {
                    config: self.config,
                    resuming_session: self.resuming_session,
                    session_id: self.session_id,
                    server_name: self.server_name,
                    randoms: self.randoms,
                    using_ems: self.using_ems,
                    transcript: self.transcript,
                    suite: self.suite,
                    server_cert_sct_list: self.server_cert_sct_list,
                    server_cert_chain: self.server_cert_chain,
                    must_issue_new_ticket: self.must_issue_new_ticket,
                })
                .handle(cx, m)
                .await
            }
            payload => Err(inappropriate_handshake_message(
                &payload,
                &[ContentType::Handshake],
                &[
                    HandshakeType::ServerKeyExchange,
                    HandshakeType::CertificateStatus,
                ],
            )),
        }
    }
}

struct ExpectCertificateStatus {
    config: Arc<ClientConfig>,
    resuming_session: Option<persist::Tls12ClientSessionValue>,
    session_id: SessionID,
    server_name: ServerName,
    randoms: ConnectionRandoms,
    using_ems: bool,
    transcript: HandshakeHash,
    suite: &'static Tls12CipherSuite,
    server_cert_sct_list: Option<SCTList>,
    server_cert_chain: CertificatePayload,
    must_issue_new_ticket: bool,
}

#[async_trait]
impl State<ClientConnectionData> for ExpectCertificateStatus {
    async fn handle(
        mut self: Box<Self>,
        cx: &mut ClientContext<'_>,
        m: Message,
    ) -> hs::NextStateOrError {
        self.transcript.add_message(&m);
        let server_cert_ocsp_response = require_handshake_msg_move!(
            m,
            HandshakeType::CertificateStatus,
            HandshakePayload::CertificateStatus
        )?
        .into_inner();

        trace!(
            "Server stapled OCSP response is {:?}",
            &server_cert_ocsp_response
        );

        let server_cert = ServerCertDetails::new(
            self.server_cert_chain,
            server_cert_ocsp_response,
            self.server_cert_sct_list,
        );

        cx.common
            .backend
            .set_server_cert_details(server_cert.clone())
            .await?;

        Ok(Box::new(ExpectServerKx {
            config: self.config,
            resuming_session: self.resuming_session,
            session_id: self.session_id,
            server_name: self.server_name,
            randoms: self.randoms,
            using_ems: self.using_ems,
            transcript: self.transcript,
            suite: self.suite,
            server_cert,
            must_issue_new_ticket: self.must_issue_new_ticket,
        }))
    }
}

struct ExpectServerKx {
    config: Arc<ClientConfig>,
    resuming_session: Option<persist::Tls12ClientSessionValue>,
    session_id: SessionID,
    server_name: ServerName,
    randoms: ConnectionRandoms,
    using_ems: bool,
    transcript: HandshakeHash,
    suite: &'static Tls12CipherSuite,
    server_cert: ServerCertDetails,
    must_issue_new_ticket: bool,
}

#[async_trait]
impl State<ClientConnectionData> for ExpectServerKx {
    async fn handle(
        mut self: Box<Self>,
        cx: &mut ClientContext<'_>,
        m: Message,
    ) -> hs::NextStateOrError {
        let opaque_kx = require_handshake_msg!(
            m,
            HandshakeType::ServerKeyExchange,
            HandshakePayload::ServerKeyExchange
        )?;
        self.transcript.add_message(&m);

        let ecdhe = match opaque_kx.unwrap_given_kxa(&self.suite.kx) {
            Some(ecdhe) => ecdhe,
            None => {
                // We only support ECDHE
                cx.common
                    .send_fatal_alert(AlertDescription::DecodeError)
                    .await?;
                return Err(Error::CorruptMessagePayload(ContentType::Handshake));
            }
        };

        // Save the signature and signed parameters for later verification.
        let mut kx_params = Vec::new();
        ecdhe.params.encode(&mut kx_params);
        let server_kx = ServerKxDetails::new(kx_params, ecdhe.dss);

        #[cfg_attr(not(feature = "logging"), allow(unused_variables))]
        {
            debug!("ECDHE curve is {:?}", ecdhe.params.curve_params);
        }

        Ok(Box::new(ExpectServerDoneOrCertReq {
            config: self.config,
            resuming_session: self.resuming_session,
            session_id: self.session_id,
            server_name: self.server_name,
            randoms: self.randoms,
            using_ems: self.using_ems,
            transcript: self.transcript,
            suite: self.suite,
            server_cert: self.server_cert,
            server_kx,
            must_issue_new_ticket: self.must_issue_new_ticket,
        }))
    }
}

async fn emit_certificate(
    transcript: &mut HandshakeHash,
    cert_chain: CertificatePayload,
    common: &mut CommonState,
) -> Result<(), Error> {
    let cert = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::Certificate,
            payload: HandshakePayload::Certificate(cert_chain),
        }),
    };

    transcript.add_message(&cert);
    common.send_msg(cert, false).await
}

async fn emit_clientkx(
    transcript: &mut HandshakeHash,
    common: &mut CommonState,
    pubkey: &PublicKey,
) -> Result<(), Error> {
    let ecpoint = PayloadU8::new(pubkey.key.clone());

    let mut buf = Vec::new();
    ecpoint.encode(&mut buf);
    let pubkey = Payload::new(buf);

    let ckx = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::ClientKeyExchange,
            payload: HandshakePayload::ClientKeyExchange(pubkey),
        }),
    };

    transcript.add_message(&ckx);
    common.send_msg(ckx, false).await
}

async fn emit_certverify(
    transcript: &mut HandshakeHash,
    signer: &dyn Signer,
    common: &mut CommonState,
) -> Result<(), Error> {
    let message = transcript
        .take_handshake_buf()
        .ok_or_else(|| Error::General("Expected transcript".to_owned()))?;

    let scheme = signer.scheme();
    let sig = signer.sign(&message)?;
    let body = DigitallySignedStruct::new(scheme, sig);

    let m = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::CertificateVerify,
            payload: HandshakePayload::CertificateVerify(body),
        }),
    };

    transcript.add_message(&m);
    common.send_msg(m, false).await
}

async fn emit_ccs(common: &mut CommonState) -> Result<(), Error> {
    let ccs = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload {}),
    };

    common.send_msg(ccs, false).await
}

async fn emit_finished(
    verify_data: &[u8],
    transcript: &mut HandshakeHash,
    common: &mut CommonState,
) -> Result<(), Error> {
    let verify_data_payload = Payload::new(verify_data);

    let f = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::Finished,
            payload: HandshakePayload::Finished(verify_data_payload),
        }),
    };

    transcript.add_message(&f);
    common.send_msg(f, true).await
}

// --- Either a CertificateRequest, or a ServerHelloDone. ---
// Existence of the CertificateRequest tells us the server is asking for
// client auth.  Otherwise we go straight to ServerHelloDone.
struct ExpectServerDoneOrCertReq {
    config: Arc<ClientConfig>,
    resuming_session: Option<persist::Tls12ClientSessionValue>,
    session_id: SessionID,
    server_name: ServerName,
    randoms: ConnectionRandoms,
    using_ems: bool,
    transcript: HandshakeHash,
    suite: &'static Tls12CipherSuite,
    server_cert: ServerCertDetails,
    server_kx: ServerKxDetails,
    must_issue_new_ticket: bool,
}

#[async_trait]
impl State<ClientConnectionData> for ExpectServerDoneOrCertReq {
    async fn handle(
        mut self: Box<Self>,
        cx: &mut ClientContext<'_>,
        m: Message,
    ) -> hs::NextStateOrError {
        if matches!(
            m.payload,
            MessagePayload::Handshake(HandshakeMessagePayload {
                payload: HandshakePayload::CertificateRequest(_),
                ..
            })
        ) {
            Box::new(ExpectCertificateRequest {
                config: self.config,
                resuming_session: self.resuming_session,
                session_id: self.session_id,
                server_name: self.server_name,
                randoms: self.randoms,
                using_ems: self.using_ems,
                transcript: self.transcript,
                suite: self.suite,
                server_cert: self.server_cert,
                server_kx: self.server_kx,
                must_issue_new_ticket: self.must_issue_new_ticket,
            })
            .handle(cx, m)
            .await
        } else {
            self.transcript.abandon_client_auth();

            Box::new(ExpectServerDone {
                config: self.config,
                resuming_session: self.resuming_session,
                session_id: self.session_id,
                server_name: self.server_name,
                randoms: self.randoms,
                using_ems: self.using_ems,
                transcript: self.transcript,
                suite: self.suite,
                server_cert: self.server_cert,
                server_kx: self.server_kx,
                client_auth: None,
                must_issue_new_ticket: self.must_issue_new_ticket,
            })
            .handle(cx, m)
            .await
        }
    }
}

struct ExpectCertificateRequest {
    config: Arc<ClientConfig>,
    resuming_session: Option<persist::Tls12ClientSessionValue>,
    session_id: SessionID,
    server_name: ServerName,
    randoms: ConnectionRandoms,
    using_ems: bool,
    transcript: HandshakeHash,
    suite: &'static Tls12CipherSuite,
    server_cert: ServerCertDetails,
    server_kx: ServerKxDetails,
    must_issue_new_ticket: bool,
}

#[async_trait]
impl State<ClientConnectionData> for ExpectCertificateRequest {
    async fn handle(
        mut self: Box<Self>,
        _cx: &mut ClientContext<'_>,
        m: Message,
    ) -> hs::NextStateOrError {
        let certreq = require_handshake_msg!(
            m,
            HandshakeType::CertificateRequest,
            HandshakePayload::CertificateRequest
        )?;
        self.transcript.add_message(&m);
        debug!("Got CertificateRequest {:?}", certreq);

        // The RFC jovially describes the design here as 'somewhat complicated'
        // and 'somewhat underspecified'.  So thanks for that.
        //
        // We ignore certreq.certtypes as a result, since the information it contains
        // is entirely duplicated in certreq.sigschemes.

        const NO_CONTEXT: Option<Vec<u8>> = None; // TLS 1.2 doesn't use a context.
        let client_auth = ClientAuthDetails::resolve(
            self.config.client_auth_cert_resolver.as_ref(),
            Some(&certreq.canames),
            &certreq.sigschemes,
            NO_CONTEXT,
        );

        Ok(Box::new(ExpectServerDone {
            config: self.config,
            resuming_session: self.resuming_session,
            session_id: self.session_id,
            server_name: self.server_name,
            randoms: self.randoms,
            using_ems: self.using_ems,
            transcript: self.transcript,
            suite: self.suite,
            server_cert: self.server_cert,
            server_kx: self.server_kx,
            client_auth: Some(client_auth),
            must_issue_new_ticket: self.must_issue_new_ticket,
        }))
    }
}

struct ExpectServerDone {
    config: Arc<ClientConfig>,
    resuming_session: Option<persist::Tls12ClientSessionValue>,
    session_id: SessionID,
    server_name: ServerName,
    randoms: ConnectionRandoms,
    using_ems: bool,
    transcript: HandshakeHash,
    suite: &'static Tls12CipherSuite,
    server_cert: ServerCertDetails,
    server_kx: ServerKxDetails,
    client_auth: Option<ClientAuthDetails>,
    must_issue_new_ticket: bool,
}

#[async_trait]
impl State<ClientConnectionData> for ExpectServerDone {
    async fn handle(
        self: Box<Self>,
        cx: &mut ClientContext<'_>,
        m: Message,
    ) -> hs::NextStateOrError {
        match m.payload {
            MessagePayload::Handshake(HandshakeMessagePayload {
                payload: HandshakePayload::ServerHelloDone,
                ..
            }) => {}
            payload => {
                return Err(inappropriate_handshake_message(
                    &payload,
                    &[ContentType::Handshake],
                    &[HandshakeType::ServerHelloDone],
                ));
            }
        }

        let mut st = *self;
        st.transcript.add_message(&m);

        cx.common.check_aligned_handshake().await?;

        trace!("Server cert is {:?}", st.server_cert.cert_chain());
        debug!("Server DNS name is {:?}", st.server_name);

        let suite = st.suite;

        // 1. Verify the cert chain.
        // 2. Verify any SCTs provided with the certificate.
        // 3. Verify that the top certificate signed their kx.
        // 4. If doing client auth, send our Certificate.
        // 5. Complete the key exchange:
        //    a) generate our kx pair
        //    b) emit a ClientKeyExchange containing it
        //    c) if doing client auth, emit a CertificateVerify
        //    d) emit a CCS
        //    e) derive the shared keys, and start encryption
        // 6. emit a Finished, our first encrypted message under the new keys.

        // 1.
        let (end_entity, intermediates) = st
            .server_cert
            .cert_chain()
            .split_first()
            .ok_or(Error::NoCertificatesPresented)?;
        let now = web_time::SystemTime::now();
        let cert_verified = match st.config.verifier.verify_server_cert(
            end_entity,
            intermediates,
            &st.server_name,
            &mut st
                .server_cert
                .scts()
                .map(|sct| sct.as_slice())
                .unwrap_or(&[])
                .iter()
                .map(|sct| sct.0.as_slice()),
            st.server_cert.ocsp_response(),
            now,
        ) {
            Ok(cert_verified) => cert_verified,
            Err(e) => return Err(hs::send_cert_error_alert(cx.common, Error::CoreError(e)).await?),
        };

        // 3.
        // Build up the contents of the signed message.
        // It's ClientHello.random || ServerHello.random || ServerKeyExchange.params
        let sig_verified = {
            let mut message = Vec::new();
            message.extend_from_slice(&st.randoms.client);
            message.extend_from_slice(&st.randoms.server);
            message.extend_from_slice(st.server_kx.kx_params());

            // Check the signature is compatible with the ciphersuite.
            let sig = st.server_kx.kx_sig();
            if !SupportedCipherSuite::from(suite).usable_for_signature_algorithm(sig.scheme.sign())
            {
                let error_message = format!(
                    "peer signed kx with wrong algorithm (got {:?} expect {:?})",
                    sig.scheme.sign(),
                    suite.sign
                );
                return Err(Error::PeerMisbehavedError(error_message));
            }

            match st.config.verifier.verify_tls12_signature(
                &message,
                &st.server_cert.cert_chain()[0],
                sig,
            ) {
                Ok(sig_verified) => sig_verified,
                Err(e) => {
                    return Err(hs::send_cert_error_alert(cx.common, Error::CoreError(e)).await?)
                }
            }
        };
        cx.common.peer_certificates = Some(st.server_cert.cert_chain().to_vec());

        // 4.
        if let Some(client_auth) = &st.client_auth {
            let certs = match client_auth {
                ClientAuthDetails::Empty { .. } => Vec::new(),
                ClientAuthDetails::Verify { certkey, .. } => certkey.cert.clone(),
            };
            emit_certificate(&mut st.transcript, certs, cx.common).await?;
        }

        // 5a.
        let ecdh_params =
            match tls12::decode_ecdh_params::<ServerECDHParams>(st.server_kx.kx_params()) {
                Some(ecdh_params) => ecdh_params,
                None => {
                    cx.common
                        .send_fatal_alert(AlertDescription::DecodeError)
                        .await?;
                    return Err(Error::CorruptMessagePayload(ContentType::Handshake));
                }
            };

        let key_share = cx.common.backend.get_client_key_share().await?;
        if key_share.group != ecdh_params.curve_params.named_group {
            return Err(Error::PeerMisbehavedError(
                "peer chose an unsupported group".to_string(),
            ));
        }

        // 5b.
        let mut transcript = st.transcript;
        emit_clientkx(&mut transcript, cx.common, &key_share).await?;
        // nb. EMS handshake hash only runs up to ClientKeyExchange.
        let ems_seed = transcript.get_current_hash();

        cx.common
            .backend
            .set_hs_hash_client_key_exchange(ems_seed.as_ref().to_vec())
            .await?;

        // 5c.
        if let Some(ClientAuthDetails::Verify { signer, .. }) = &st.client_auth {
            emit_certverify(&mut transcript, signer.as_ref(), cx.common).await?;
        }

        // 5d.
        emit_ccs(cx.common).await?;

        // 5e. Now commit secrets.
        let server_key_share =
            PublicKey::new(ecdh_params.curve_params.named_group, &ecdh_params.public.0);

        cx.common
            .backend
            .set_server_kx_details(st.server_kx)
            .await?;
        cx.common
            .backend
            .set_server_key_share(server_key_share)
            .await?;
        cx.common.backend.prepare_encryption().await?;
        cx.common.record_layer.prepare_message_encrypter();
        cx.common.record_layer.prepare_message_decrypter();
        cx.common.record_layer.start_encrypting();

        st.config
            .key_log
            .log("CLIENT_RANDOM", &st.randoms.client, &[]);

        // 6.
        let hs = transcript.get_current_hash();
        let cf = cx
            .common
            .backend
            .get_client_finished_vd(hs.as_ref().to_vec())
            .await?;
        emit_finished(&cf, &mut transcript, cx.common).await?;

        if st.must_issue_new_ticket {
            Ok(Box::new(ExpectNewTicket {
                config: st.config,
                resuming_session: st.resuming_session,
                session_id: st.session_id,
                server_name: st.server_name,
                using_ems: st.using_ems,
                transcript,
                resuming: false,
                cert_verified,
                sig_verified,
            }))
        } else {
            Ok(Box::new(ExpectCcs {
                config: st.config,
                resuming_session: st.resuming_session,
                session_id: st.session_id,
                server_name: st.server_name,
                using_ems: st.using_ems,
                transcript,
                ticket: None,
                resuming: false,
                cert_verified,
                sig_verified,
            }))
        }
    }
}

struct ExpectNewTicket {
    config: Arc<ClientConfig>,
    resuming_session: Option<persist::Tls12ClientSessionValue>,
    session_id: SessionID,
    server_name: ServerName,
    using_ems: bool,
    transcript: HandshakeHash,
    resuming: bool,
    cert_verified: verify::ServerCertVerified,
    sig_verified: verify::HandshakeSignatureValid,
}

#[async_trait]
impl State<ClientConnectionData> for ExpectNewTicket {
    async fn handle(
        mut self: Box<Self>,
        _cx: &mut ClientContext<'_>,
        m: Message,
    ) -> hs::NextStateOrError {
        self.transcript.add_message(&m);

        let nst = require_handshake_msg_move!(
            m,
            HandshakeType::NewSessionTicket,
            HandshakePayload::NewSessionTicket
        )?;

        Ok(Box::new(ExpectCcs {
            config: self.config,
            resuming_session: self.resuming_session,
            session_id: self.session_id,
            server_name: self.server_name,
            using_ems: self.using_ems,
            transcript: self.transcript,
            ticket: Some(nst),
            resuming: self.resuming,
            cert_verified: self.cert_verified,
            sig_verified: self.sig_verified,
        }))
    }
}

// -- Waiting for their CCS --
struct ExpectCcs {
    config: Arc<ClientConfig>,
    resuming_session: Option<persist::Tls12ClientSessionValue>,
    session_id: SessionID,
    server_name: ServerName,
    using_ems: bool,
    transcript: HandshakeHash,
    ticket: Option<NewSessionTicketPayload>,
    resuming: bool,
    cert_verified: verify::ServerCertVerified,
    sig_verified: verify::HandshakeSignatureValid,
}

#[async_trait]
impl State<ClientConnectionData> for ExpectCcs {
    async fn handle(
        self: Box<Self>,
        cx: &mut ClientContext<'_>,
        m: Message,
    ) -> hs::NextStateOrError {
        match m.payload {
            MessagePayload::ChangeCipherSpec(..) => {}
            payload => {
                return Err(inappropriate_message(
                    &payload,
                    &[ContentType::ChangeCipherSpec],
                ));
            }
        }
        // CCS should not be received interleaved with fragmented handshake-level
        // message.
        cx.common.check_aligned_handshake().await?;

        // nb. msgs layer validates trivial contents of CCS
        cx.common.record_layer.start_decrypting();

        Ok(Box::new(ExpectFinished {
            config: self.config,
            resuming_session: self.resuming_session,
            session_id: self.session_id,
            server_name: self.server_name,
            using_ems: self.using_ems,
            transcript: self.transcript,
            ticket: self.ticket,
            resuming: self.resuming,
            cert_verified: self.cert_verified,
            sig_verified: self.sig_verified,
        }))
    }
}

struct ExpectFinished {
    config: Arc<ClientConfig>,
    resuming_session: Option<persist::Tls12ClientSessionValue>,
    session_id: SessionID,
    server_name: ServerName,
    using_ems: bool,
    transcript: HandshakeHash,
    ticket: Option<NewSessionTicketPayload>,
    resuming: bool,
    cert_verified: verify::ServerCertVerified,
    sig_verified: verify::HandshakeSignatureValid,
}

// impl ExpectFinished {
//     // -- Waiting for their finished --
//     fn save_session(&mut self, cx: &mut ClientContext<'_>) {
//         // Save a ticket.  If we got a new ticket, save that.  Otherwise, save the
//         // original ticket again.
//         let (mut ticket, lifetime) = match self.ticket.take() {
//             Some(nst) => (nst.ticket.0, nst.lifetime_hint),
//             None => (Vec::new(), 0),
//         };

//         if ticket.is_empty() {
//             if let Some(resuming_session) = &mut self.resuming_session {
//                 ticket = resuming_session.take_ticket();
//             }
//         }

//         if self.session_id.is_empty() && ticket.is_empty() {
//             debug!("Session not saved: server didn't allocate id or ticket");
//             return;
//         }

//         let time_now = match TimeBase::now() {
//             Ok(time_now) => time_now,
//             Err(e) => {
//                 debug!("Session not saved: {}", e);
//                 return;
//             }
//         };

//         let key = persist::ClientSessionKey::session_for_server_name(&self.server_name);
//         let value = persist::Tls12ClientSessionValue::new(
//             self.secrets.suite(),
//             self.session_id,
//             ticket,
//             self.secrets.get_master_secret(),
//             cx.common.peer_certificates.clone().unwrap_or_default(),
//             time_now,
//             lifetime,
//             self.using_ems,
//         );

//         let worked = self
//             .config
//             .session_storage
//             .put(key.get_encoding(), value.get_encoding());

//         if worked {
//             debug!("Session saved");
//         } else {
//             debug!("Session not saved");
//         }
//     }
// }

#[async_trait]
impl State<ClientConnectionData> for ExpectFinished {
    async fn handle(
        self: Box<Self>,
        cx: &mut ClientContext<'_>,
        m: Message,
    ) -> hs::NextStateOrError {
        let mut st = *self;
        let finished =
            require_handshake_msg!(m, HandshakeType::Finished, HandshakePayload::Finished)?;

        cx.common.check_aligned_handshake().await?;

        // Work out what verify_data we expect.
        let vh = st.transcript.get_current_hash();
        let expect_verify_data = cx
            .common
            .backend
            .get_server_finished_vd(vh.as_ref().to_vec())
            .await?;

        // Constant-time verification of this is relatively unimportant: they only
        // get one chance.  But it can't hurt.
        let _fin_verified =
            match constant_time::verify_slices_are_equal(&expect_verify_data, &finished.0) {
                Ok(()) => verify::FinishedMessageVerified::assertion(),
                Err(_) => {
                    cx.common
                        .send_fatal_alert(AlertDescription::DecryptError)
                        .await?;
                    return Err(Error::DecryptError);
                }
            };

        // Hash this message too.
        st.transcript.add_message(&m);

        // st.save_session(cx);

        if st.resuming {
            emit_ccs(cx.common).await?;
            cx.common.record_layer.start_encrypting();
            emit_finished(&expect_verify_data, &mut st.transcript, cx.common).await?;
        }

        cx.common.start_traffic().await?;
        Ok(Box::new(ExpectTraffic {
            _cert_verified: st.cert_verified,
            _sig_verified: st.sig_verified,
            _fin_verified,
        }))
    }
}

// -- Traffic transit state --
struct ExpectTraffic {
    _cert_verified: verify::ServerCertVerified,
    _sig_verified: verify::HandshakeSignatureValid,
    _fin_verified: verify::FinishedMessageVerified,
}

#[async_trait]
impl State<ClientConnectionData> for ExpectTraffic {
    async fn handle(
        self: Box<Self>,
        cx: &mut ClientContext<'_>,
        m: Message,
    ) -> hs::NextStateOrError {
        match m.payload {
            MessagePayload::ApplicationData(payload) => cx.common.take_received_plaintext(payload),
            payload => {
                return Err(inappropriate_message(
                    &payload,
                    &[ContentType::ApplicationData],
                ));
            }
        }
        Ok(self)
    }

    fn export_keying_material(
        &self,
        _output: &mut [u8],
        _label: &[u8],
        _context: Option<&[u8]>,
    ) -> Result<(), Error> {
        Err(Error::General(
            "client does not support exporting keying material".to_string(),
        ))
    }
}
