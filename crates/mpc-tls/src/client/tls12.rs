use crate::{
    client::{
        ClientConfig, ServerName,
        check::{inappropriate_handshake_message, inappropriate_message},
        error::Error,
        hash_hs::HandshakeHash,
        hs::{self, ClientAuthDetails, Handshake, ServerCertDetails},
        sign::Signer,
        verify,
    },
    leader::{ConnectionRandoms, HandshakeData, Live},
};
#[allow(deprecated)]
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
            HandshakeMessagePayload, HandshakePayload, Random, SCTList, ServerECDHParams,
        },
        message::{Message, MessagePayload},
    },
    suites::{SupportedCipherSuite, Tls12CipherSuite, tls12},
};
use tracing::{debug, trace};

pub(crate) use server_hello::CompleteServerHelloHandling;

mod server_hello {
    use tls_core::msgs::{
        enums::ExtensionType,
        handshake::{HasServerExtensions, ServerHelloPayload},
    };

    use super::*;

    pub(crate) struct CompleteServerHelloHandling {
        pub(crate) config: Arc<ClientConfig>,
        pub(crate) server_name: ServerName,
        pub(crate) randoms: ConnectionRandoms,
        pub(crate) transcript: HandshakeHash,
    }

    impl CompleteServerHelloHandling {
        pub(crate) async fn handle_server_hello(
            mut self,
            cx: &mut Live,
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
                    .illegal_param("downgrade to TLS1.2 when TLS1.3 is supported")
                    .await?);
            }

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

            Ok(Handshake::Tls12ExpectCertificate(Box::new(
                ExpectCertificate {
                    config: self.config,
                    server_name: self.server_name,
                    randoms: self.randoms,
                    transcript: self.transcript,
                    suite,
                    may_send_cert_status,
                    server_cert_sct_list,
                },
            )))
        }
    }
}

pub(crate) struct ExpectCertificate {
    config: Arc<ClientConfig>,
    server_name: ServerName,
    randoms: ConnectionRandoms,
    transcript: HandshakeHash,
    pub(crate) suite: &'static Tls12CipherSuite,
    may_send_cert_status: bool,
    server_cert_sct_list: Option<SCTList>,
}

impl ExpectCertificate {
    pub(crate) async fn handle(
        mut self: Box<Self>,
        _cx: &mut Live,
        m: Message,
    ) -> hs::NextStateOrError {
        self.transcript.add_message(&m);
        let server_cert_chain = require_handshake_msg_move!(
            m,
            HandshakeType::Certificate,
            HandshakePayload::Certificate
        )?;

        if self.may_send_cert_status {
            Ok(Handshake::Tls12ExpectCertificateStatusOrServerKx(Box::new(
                ExpectCertificateStatusOrServerKx {
                    config: self.config,
                    server_name: self.server_name,
                    randoms: self.randoms,
                    transcript: self.transcript,
                    suite: self.suite,
                    server_cert_sct_list: self.server_cert_sct_list,
                    server_cert_chain,
                },
            )))
        } else {
            let server_cert =
                ServerCertDetails::new(server_cert_chain, vec![], self.server_cert_sct_list);

            Ok(Handshake::Tls12ExpectServerKx(Box::new(ExpectServerKx {
                config: self.config,
                server_name: self.server_name,
                randoms: self.randoms,
                transcript: self.transcript,
                suite: self.suite,
                server_cert,
            })))
        }
    }
}

pub(crate) struct ExpectCertificateStatusOrServerKx {
    config: Arc<ClientConfig>,
    server_name: ServerName,
    randoms: ConnectionRandoms,
    transcript: HandshakeHash,
    suite: &'static Tls12CipherSuite,
    server_cert_sct_list: Option<SCTList>,
    server_cert_chain: CertificatePayload,
}

impl ExpectCertificateStatusOrServerKx {
    pub(crate) async fn handle(self: Box<Self>, cx: &mut Live, m: Message) -> hs::NextStateOrError {
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

                Box::new(ExpectServerKx {
                    config: self.config,
                    server_name: self.server_name,
                    randoms: self.randoms,
                    transcript: self.transcript,
                    suite: self.suite,
                    server_cert: server_cert_details,
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
                    server_name: self.server_name,
                    randoms: self.randoms,
                    transcript: self.transcript,
                    suite: self.suite,
                    server_cert_sct_list: self.server_cert_sct_list,
                    server_cert_chain: self.server_cert_chain,
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

pub(crate) struct ExpectCertificateStatus {
    config: Arc<ClientConfig>,
    server_name: ServerName,
    randoms: ConnectionRandoms,
    transcript: HandshakeHash,
    suite: &'static Tls12CipherSuite,
    server_cert_sct_list: Option<SCTList>,
    server_cert_chain: CertificatePayload,
}

impl ExpectCertificateStatus {
    pub(crate) async fn handle(
        mut self: Box<Self>,
        _cx: &mut Live,
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

        Ok(Handshake::Tls12ExpectServerKx(Box::new(ExpectServerKx {
            config: self.config,
            server_name: self.server_name,
            randoms: self.randoms,
            transcript: self.transcript,
            suite: self.suite,
            server_cert,
        })))
    }
}

pub(crate) struct ExpectServerKx {
    config: Arc<ClientConfig>,
    server_name: ServerName,
    randoms: ConnectionRandoms,
    transcript: HandshakeHash,
    suite: &'static Tls12CipherSuite,
    server_cert: ServerCertDetails,
}

impl ExpectServerKx {
    pub(crate) async fn handle(
        mut self: Box<Self>,
        cx: &mut Live,
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
                cx.send_fatal_alert(AlertDescription::DecodeError).await?;
                return Err(Error::CorruptMessagePayload(ContentType::Handshake));
            }
        };

        // Save the signature and signed parameters for later verification.
        let mut kx_params = Vec::new();
        ecdhe.params.encode(&mut kx_params);
        let server_kx = ServerKxDetails::new(kx_params, ecdhe.dss);

        {
            debug!("ECDHE curve is {:?}", ecdhe.params.curve_params);
        }

        Ok(Handshake::Tls12ExpectServerDoneOrCertReq(Box::new(
            ExpectServerDoneOrCertReq {
                config: self.config,
                server_name: self.server_name,
                randoms: self.randoms,
                transcript: self.transcript,
                suite: self.suite,
                server_cert: self.server_cert,
                server_kx,
            },
        )))
    }
}

async fn emit_certificate(
    transcript: &mut HandshakeHash,
    cert_chain: CertificatePayload,
    common: &mut Live,
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
    common: &mut Live,
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
    common: &mut Live,
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

async fn emit_ccs(common: &mut Live) -> Result<(), Error> {
    let ccs = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload {}),
    };

    common.send_msg(ccs, false).await
}

async fn emit_finished(
    verify_data: &[u8],
    transcript: &mut HandshakeHash,
    common: &mut Live,
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
pub(crate) struct ExpectServerDoneOrCertReq {
    config: Arc<ClientConfig>,
    server_name: ServerName,
    randoms: ConnectionRandoms,
    transcript: HandshakeHash,
    suite: &'static Tls12CipherSuite,
    server_cert: ServerCertDetails,
    server_kx: ServerKxDetails,
}

impl ExpectServerDoneOrCertReq {
    pub(crate) async fn handle(
        mut self: Box<Self>,
        cx: &mut Live,
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
                server_name: self.server_name,
                randoms: self.randoms,
                transcript: self.transcript,
                suite: self.suite,
                server_cert: self.server_cert,
                server_kx: self.server_kx,
            })
            .handle(cx, m)
            .await
        } else {
            self.transcript.abandon_client_auth();

            Box::new(ExpectServerDone {
                config: self.config,
                server_name: self.server_name,
                randoms: self.randoms,
                transcript: self.transcript,
                suite: self.suite,
                server_cert: self.server_cert,
                server_kx: self.server_kx,
                client_auth: None,
            })
            .handle(cx, m)
            .await
        }
    }
}

pub(crate) struct ExpectCertificateRequest {
    config: Arc<ClientConfig>,
    server_name: ServerName,
    randoms: ConnectionRandoms,
    transcript: HandshakeHash,
    suite: &'static Tls12CipherSuite,
    server_cert: ServerCertDetails,
    server_kx: ServerKxDetails,
}

impl ExpectCertificateRequest {
    pub(crate) async fn handle(
        mut self: Box<Self>,
        _cx: &mut Live,
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

        Ok(Handshake::Tls12ExpectServerDone(Box::new(ExpectServerDone {
            config: self.config,
            server_name: self.server_name,
            randoms: self.randoms,
            transcript: self.transcript,
            suite: self.suite,
            server_cert: self.server_cert,
            server_kx: self.server_kx,
            client_auth: Some(client_auth),
        })))
    }
}

pub(crate) struct ExpectServerDone {
    config: Arc<ClientConfig>,
    server_name: ServerName,
    randoms: ConnectionRandoms,
    transcript: HandshakeHash,
    suite: &'static Tls12CipherSuite,
    server_cert: ServerCertDetails,
    server_kx: ServerKxDetails,
    client_auth: Option<ClientAuthDetails>,
}

impl ExpectServerDone {
    pub(crate) async fn handle(self: Box<Self>, cx: &mut Live, m: Message) -> hs::NextStateOrError {
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

        cx.check_aligned_handshake().await?;

        trace!("Server cert is {:?}", st.server_cert.cert_chain());
        debug!("Server DNS name is {:?}", st.server_name);

        let suite = st.suite;

        // 1. Verify the cert chain.
        // 2. Verify any SCTs provided with the certificate.
        // 3. Verify that the top certificate signed their kx.
        // 4. If doing client auth, send our Certificate.
        // 5. Complete the key exchange:
        //
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
            Err(e) => return Err(hs::send_cert_error_alert(cx, Error::CoreError(e)).await?),
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
            if !SupportedCipherSuite::from(suite).usable_for_signature_algorithm(sig.scheme.sign()) {
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
                Err(e) => return Err(hs::send_cert_error_alert(cx, Error::CoreError(e)).await?),
            }
        };
        // 4.
        if let Some(client_auth) = &st.client_auth {
            let certs = match client_auth {
                ClientAuthDetails::Empty { .. } => Vec::new(),
                ClientAuthDetails::Verify { certkey, .. } => certkey.cert.clone(),
            };
            emit_certificate(&mut st.transcript, certs, cx).await?;
        }

        // 5a.
        let ecdh_params =
            match tls12::decode_ecdh_params::<ServerECDHParams>(st.server_kx.kx_params()) {
                Some(ecdh_params) => ecdh_params,
                None => {
                    cx.send_fatal_alert(AlertDescription::DecodeError).await?;
                    return Err(Error::CorruptMessagePayload(ContentType::Handshake));
                }
            };

        let key_share = cx.client_key_share()?;
        if key_share.group != ecdh_params.curve_params.named_group {
            return Err(Error::PeerMisbehavedError(
                "peer chose an unsupported group".to_string(),
            ));
        }

        // 5b.
        let mut transcript = st.transcript;
        emit_clientkx(&mut transcript, cx, &key_share).await?;

        // 5c.
        if let Some(ClientAuthDetails::Verify { signer, .. }) = &st.client_auth {
            emit_certverify(&mut transcript, signer.as_ref(), cx).await?;
        }

        // 5d.
        emit_ccs(cx).await?;

        // 5e. Now commit secrets.
        let server_key_share =
            PublicKey::new(ecdh_params.curve_params.named_group, &ecdh_params.public.0);

        cx.prepare_encryption(HandshakeData {
            server_random: Random(st.randoms.server),
            server_key: server_key_share,
            server_cert_details: st.server_cert,
            server_kx_details: st.server_kx,
        })
        .await?;
        cx.start_encrypting();

        // 6.
        let hs = transcript.get_current_hash();
        let cf = cx.get_client_finished_vd(hs.as_ref().to_vec()).await?;
        emit_finished(&cf, &mut transcript, cx).await?;

        Ok(Handshake::Tls12ExpectCcs(Box::new(ExpectCcs {
            transcript,
            cert_verified,
            sig_verified,
        })))
    }
}

// -- Waiting for their CCS --
pub(crate) struct ExpectCcs {
    transcript: HandshakeHash,
    cert_verified: verify::ServerCertVerified,
    sig_verified: verify::HandshakeSignatureValid,
}

impl ExpectCcs {
    pub(crate) async fn handle(self: Box<Self>, cx: &mut Live, m: Message) -> hs::NextStateOrError {
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
        cx.check_aligned_handshake().await?;

        // nb. msgs layer validates trivial contents of CCS
        cx.start_decrypting();

        Ok(Handshake::Tls12ExpectFinished(Box::new(ExpectFinished {
            transcript: self.transcript,
            cert_verified: self.cert_verified,
            sig_verified: self.sig_verified,
        })))
    }
}

pub(crate) struct ExpectFinished {
    transcript: HandshakeHash,
    cert_verified: verify::ServerCertVerified,
    sig_verified: verify::HandshakeSignatureValid,
}

impl ExpectFinished {
    pub(crate) async fn handle(self: Box<Self>, cx: &mut Live, m: Message) -> hs::NextStateOrError {
        let mut st = *self;
        let finished =
            require_handshake_msg!(m, HandshakeType::Finished, HandshakePayload::Finished)?;

        cx.check_aligned_handshake().await?;

        // Work out what verify_data we expect.
        let vh = st.transcript.get_current_hash();
        let expect_verify_data = cx.get_server_finished_vd(vh.as_ref().to_vec()).await?;

        // Constant-time verification of this is relatively unimportant: they only
        // get one chance.  But it can't hurt.
        #[allow(deprecated)]
        let _fin_verified =
            match constant_time::verify_slices_are_equal(&expect_verify_data, &finished.0) {
                Ok(()) => verify::FinishedMessageVerified::assertion(),
                Err(_) => {
                    cx.send_fatal_alert(AlertDescription::DecryptError).await?;
                    return Err(Error::DecryptError);
                }
            };

        // Hash this message too.
        st.transcript.add_message(&m);

        cx.start_traffic().await?;
        Ok(Handshake::Tls12ExpectTraffic(Box::new(ExpectTraffic {
            _cert_verified: st.cert_verified,
            _sig_verified: st.sig_verified,
            _fin_verified,
        })))
    }
}

// -- Traffic transit state --
pub(crate) struct ExpectTraffic {
    _cert_verified: verify::ServerCertVerified,
    _sig_verified: verify::HandshakeSignatureValid,
    _fin_verified: verify::FinishedMessageVerified,
}

impl ExpectTraffic {
    pub(crate) async fn handle(self: Box<Self>, cx: &mut Live, m: Message) -> hs::NextStateOrError {
        match m.payload {
            MessagePayload::ApplicationData(payload) => cx.take_received_plaintext(payload),
            payload => {
                return Err(inappropriate_message(
                    &payload,
                    &[ContentType::ApplicationData],
                ));
            }
        }
        Ok(Handshake::Tls12ExpectTraffic(self))
    }
}
