use tracing::{debug, trace, warn};
use crate::client::{
    ClientConfig, ServerName,
    check::inappropriate_handshake_message,
    conn::{CommonState, State},
    error::Error,
    hash_hs::HandshakeHash,
    hs::{self, ClientAuthDetails, ClientHelloDetails, ServerCertDetails},
    sign, verify,
};
#[allow(deprecated)]
use ring::constant_time;
use tls_core::{
    key::PublicKey,
    msgs::{
        base::{Payload, PayloadU8},
        ccs::ChangeCipherSpecPayload,
        enums::{
            AlertDescription, ContentType, ExtensionType, HandshakeType, KeyUpdateRequest,
            ProtocolVersion, SignatureScheme,
        },
        handshake::{
            CertificateEntry, CertificatePayloadTLS13, DigitallySignedStruct, EncryptedExtensions,
            HandshakeMessagePayload, HandshakePayload, HasServerExtensions,
            NewSessionTicketPayloadTLS13, ServerHelloPayload,
        },
        message::{Message, MessagePayload},
    },
};

use crate::client::sign::{CertifiedKey, Signer};
use async_trait::async_trait;
use std::sync::Arc;

// Extensions we expect in plaintext in the ServerHello.
static ALLOWED_PLAINTEXT_EXTS: &[ExtensionType] = &[
    ExtensionType::KeyShare,
    ExtensionType::PreSharedKey,
    ExtensionType::SupportedVersions,
];

// Only the intersection of things we offer, and those disallowed
// in TLS1.3
static DISALLOWED_TLS13_EXTS: &[ExtensionType] = &[
    ExtensionType::ECPointFormats,
    ExtensionType::SessionTicket,
    ExtensionType::RenegotiationInfo,
    ExtensionType::ExtendedMasterSecret,
];

/// The MPC backend only supports the TLS 1.2 key schedule. The TLS 1.3
/// message handling in this module is retained for future use, with the
/// key-schedule operations stubbed out by this error.
fn unsupported() -> Result<(), Error> {
    Err(Error::General(
        "TLS 1.3 is not supported by the MPC backend".to_string(),
    ))
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_server_hello(
    config: Arc<ClientConfig>,
    cx: &mut CommonState,
    server_hello: &ServerHelloPayload,
    server_name: ServerName,
    transcript: HandshakeHash,
    hello: ClientHelloDetails,
    our_key_share: PublicKey,
    mut sent_tls13_fake_ccs: bool,
) -> hs::NextStateOrError {
    validate_server_hello(cx, server_hello).await?;

    let their_key_share = match server_hello.get_key_share() {
        Some(ks) => ks,
        None => {
            cx
                .send_fatal_alert(AlertDescription::MissingExtension)
                .await?;
            return Err(Error::PeerMisbehavedError("missing key share".to_string()));
        }
    };

    if our_key_share.group != their_key_share.group {
        return Err(cx.illegal_param("wrong group for key share").await?);
    }

    // if let Some(ref resuming) = resuming_session {
    //     let resuming_suite = match suite.can_resume_from(resuming.suite()) {
    //         Some(resuming) => resuming,
    //         None => {
    //             return Err(cx
    //                 .common
    //                 .illegal_param("server resuming incompatible suite")
    //                 .await);
    //         }
    //     };

    //     if server_hello.get_psk_index() != Some(0) {
    //         return Err(cx.illegal_param("server selected invalid
    // psk").await);     }

    //     debug!("Resuming using PSK");
    //     // The key schedule has been initialized and set in fill_in_psk_binder()
    // } else {
    //     return Err(Error::PeerMisbehavedError(
    //         "server selected unoffered psk".to_string(),
    //     ));
    // }

    // // Remember what KX group the server liked for next time.
    // save_kx_hint(&config, &server_name, their_key_share.group);

    // If we change keying when a subsequent handshake message is being joined,
    // the two halves will have different record layer protections.  Disallow this.
    cx.check_aligned_handshake().await?;

    // Switching to the TLS 1.3 handshake keys is not supported by the MPC
    // backend.
    unsupported()?;

    emit_fake_ccs(&mut sent_tls13_fake_ccs, cx).await?;

    Ok(Box::new(ExpectEncryptedExtensions {
        config,
        server_name,
        transcript,
        hello,
    }))
}

async fn validate_server_hello(
    common: &mut CommonState,
    server_hello: &ServerHelloPayload,
) -> Result<(), Error> {
    for ext in &server_hello.extensions {
        if !ALLOWED_PLAINTEXT_EXTS.contains(&ext.get_type()) {
            common
                .send_fatal_alert(AlertDescription::UnsupportedExtension)
                .await?;
            return Err(Error::PeerMisbehavedError(
                "server sent unexpected cleartext ext".to_string(),
            ));
        }
    }

    Ok(())
}

pub(super) async fn emit_fake_ccs(
    sent_tls13_fake_ccs: &mut bool,
    common: &mut CommonState,
) -> Result<(), Error> {
    if std::mem::replace(sent_tls13_fake_ccs, true) {
        return Ok(());
    }

    let m = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload {}),
    };
    common.send_msg(m, false).await
}

async fn validate_encrypted_extensions(
    common: &mut CommonState,
    hello: &ClientHelloDetails,
    exts: &EncryptedExtensions,
) -> Result<(), Error> {
    if exts.has_duplicate_extension() {
        common
            .send_fatal_alert(AlertDescription::DecodeError)
            .await?;
        return Err(Error::PeerMisbehavedError(
            "server sent duplicate encrypted extensions".to_string(),
        ));
    }

    if hello.server_sent_unsolicited_extensions(exts, &[]) {
        common
            .send_fatal_alert(AlertDescription::UnsupportedExtension)
            .await?;
        let msg = "server sent unsolicited encrypted extension".to_string();
        return Err(Error::PeerMisbehavedError(msg));
    }

    for ext in exts {
        if ALLOWED_PLAINTEXT_EXTS.contains(&ext.get_type())
            || DISALLOWED_TLS13_EXTS.contains(&ext.get_type())
        {
            common
                .send_fatal_alert(AlertDescription::UnsupportedExtension)
                .await?;
            let msg = "server sent inappropriate encrypted extension".to_string();
            return Err(Error::PeerMisbehavedError(msg));
        }
    }

    Ok(())
}

struct ExpectEncryptedExtensions {
    config: Arc<ClientConfig>,
    server_name: ServerName,
    transcript: HandshakeHash,
    hello: ClientHelloDetails,
}

#[async_trait]
impl State for ExpectEncryptedExtensions {
    async fn handle(
        mut self: Box<Self>,
        cx: &mut CommonState,
        m: Message,
    ) -> hs::NextStateOrError {
        let exts = require_handshake_msg!(
            m,
            HandshakeType::EncryptedExtensions,
            HandshakePayload::EncryptedExtensions
        )?;
        debug!("TLS1.3 encrypted extensions: {:?}", exts);
        self.transcript.add_message(&m);

        validate_encrypted_extensions(cx, &self.hello, exts).await?;
        hs::process_alpn_protocol(cx, &self.config, exts.get_alpn_protocol()).await?;

        if exts.early_data_extension_offered() {
            let msg = "server sent early data extension without resumption".to_string();
            return Err(Error::PeerMisbehavedError(msg));
        }

        Ok(Box::new(ExpectCertificateOrCertReq {
            config: self.config,
            server_name: self.server_name,
            transcript: self.transcript,
            may_send_sct_list: self.hello.server_may_send_sct_list(),
        }))
    }
}

struct ExpectCertificateOrCertReq {
    config: Arc<ClientConfig>,
    server_name: ServerName,
    transcript: HandshakeHash,
    may_send_sct_list: bool,
}

#[async_trait]
impl State for ExpectCertificateOrCertReq {
    async fn handle(
        self: Box<Self>,
        cx: &mut CommonState,
        m: Message,
    ) -> hs::NextStateOrError {
        match m.payload {
            MessagePayload::Handshake(HandshakeMessagePayload {
                payload: HandshakePayload::CertificateTLS13(..),
                ..
            }) => {
                Box::new(ExpectCertificate {
                    config: self.config,
                    server_name: self.server_name,
                    transcript: self.transcript,
                    may_send_sct_list: self.may_send_sct_list,
                    client_auth: None,
                })
                .handle(cx, m)
                .await
            }
            MessagePayload::Handshake(HandshakeMessagePayload {
                payload: HandshakePayload::CertificateRequestTLS13(..),
                ..
            }) => {
                Box::new(ExpectCertificateRequest {
                    config: self.config,
                    server_name: self.server_name,
                    transcript: self.transcript,
                    may_send_sct_list: self.may_send_sct_list,
                })
                .handle(cx, m)
                .await
            }
            payload => Err(inappropriate_handshake_message(
                &payload,
                &[ContentType::Handshake],
                &[
                    HandshakeType::Certificate,
                    HandshakeType::CertificateRequest,
                ],
            )),
        }
    }
}

// TLS1.3 version of CertificateRequest handling.  We then move to expecting the
// server Certificate. Unfortunately the CertificateRequest type changed in an
// annoying way in TLS1.3.
struct ExpectCertificateRequest {
    config: Arc<ClientConfig>,
    server_name: ServerName,
    transcript: HandshakeHash,
    may_send_sct_list: bool,
}

#[async_trait]
impl State for ExpectCertificateRequest {
    async fn handle(
        mut self: Box<Self>,
        cx: &mut CommonState,
        m: Message,
    ) -> hs::NextStateOrError {
        let certreq = &require_handshake_msg!(
            m,
            HandshakeType::CertificateRequest,
            HandshakePayload::CertificateRequestTLS13
        )?;
        self.transcript.add_message(&m);
        debug!("Got CertificateRequest {:?}", certreq);

        // Fortunately the problems here in TLS1.2 and prior are corrected in
        // TLS1.3.

        // Must be empty during handshake.
        if !certreq.context.0.is_empty() {
            warn!("Server sent non-empty certreq context");
            cx
                .send_fatal_alert(AlertDescription::DecodeError)
                .await?;
            return Err(Error::CorruptMessagePayload(ContentType::Handshake));
        }

        let tls13_sign_schemes = sign::supported_sign_tls13();
        let no_sigschemes = Vec::new();
        let compat_sigschemes = certreq
            .get_sigalgs_extension()
            .unwrap_or(&no_sigschemes)
            .iter()
            .cloned()
            .filter(|scheme| tls13_sign_schemes.contains(scheme))
            .collect::<Vec<SignatureScheme>>();

        if compat_sigschemes.is_empty() {
            cx
                .send_fatal_alert(AlertDescription::HandshakeFailure)
                .await?;
            return Err(Error::PeerIncompatibleError(
                "server sent bad certreq schemes".to_string(),
            ));
        }

        let client_auth = ClientAuthDetails::resolve(
            self.config.client_auth_cert_resolver.as_ref(),
            certreq.get_authorities_extension(),
            &compat_sigschemes,
            Some(certreq.context.0.clone()),
        );

        Ok(Box::new(ExpectCertificate {
            config: self.config,
            server_name: self.server_name,
            transcript: self.transcript,
            may_send_sct_list: self.may_send_sct_list,
            client_auth: Some(client_auth),
        }))
    }
}

struct ExpectCertificate {
    config: Arc<ClientConfig>,
    server_name: ServerName,
    transcript: HandshakeHash,
    may_send_sct_list: bool,
    client_auth: Option<ClientAuthDetails>,
}

#[async_trait]
impl State for ExpectCertificate {
    async fn handle(
        mut self: Box<Self>,
        cx: &mut CommonState,
        m: Message,
    ) -> hs::NextStateOrError {
        let cert_chain = require_handshake_msg!(
            m,
            HandshakeType::Certificate,
            HandshakePayload::CertificateTLS13
        )?;
        self.transcript.add_message(&m);

        // This is only non-empty for client auth.
        if !cert_chain.context.0.is_empty() {
            warn!("certificate with non-empty context during handshake");
            cx
                .send_fatal_alert(AlertDescription::DecodeError)
                .await?;
            return Err(Error::CorruptMessagePayload(ContentType::Handshake));
        }

        if cert_chain.any_entry_has_duplicate_extension()
            || cert_chain.any_entry_has_unknown_extension()
        {
            warn!("certificate chain contains unsolicited/unknown extension");
            cx
                .send_fatal_alert(AlertDescription::UnsupportedExtension)
                .await?;
            return Err(Error::PeerMisbehavedError(
                "bad cert chain extensions".to_string(),
            ));
        }

        let server_cert = ServerCertDetails::new(
            cert_chain.convert(),
            cert_chain.get_end_entity_ocsp(),
            cert_chain.get_end_entity_scts(),
        );

        if let Some(sct_list) = server_cert.scts() {
            if hs::sct_list_is_invalid(sct_list) {
                let error_msg = "server sent invalid SCT list".to_string();
                return Err(Error::PeerMisbehavedError(error_msg));
            }

            if !self.may_send_sct_list {
                let error_msg = "server sent unsolicited SCT list".to_string();
                return Err(Error::PeerMisbehavedError(error_msg));
            }
        }

        Ok(Box::new(ExpectCertificateVerify {
            config: self.config,
            server_name: self.server_name,
            transcript: self.transcript,
            server_cert,
            client_auth: self.client_auth,
        }))
    }
}

// --- TLS1.3 CertificateVerify ---
struct ExpectCertificateVerify {
    config: Arc<ClientConfig>,
    server_name: ServerName,
    transcript: HandshakeHash,
    server_cert: ServerCertDetails,
    client_auth: Option<ClientAuthDetails>,
}

#[async_trait]
impl State for ExpectCertificateVerify {
    async fn handle(
        mut self: Box<Self>,
        cx: &mut CommonState,
        m: Message,
    ) -> hs::NextStateOrError {
        let cert_verify = require_handshake_msg!(
            m,
            HandshakeType::CertificateVerify,
            HandshakePayload::CertificateVerify
        )?;

        trace!("Server cert is {:?}", self.server_cert.cert_chain());

        // 1. Verify the certificate chain.
        let (end_entity, intermediates) = self
            .server_cert
            .cert_chain()
            .split_first()
            .ok_or(Error::NoCertificatesPresented)?;
        let now = web_time::SystemTime::now();
        let cert_verified = match self.config.verifier.verify_server_cert(
            end_entity,
            intermediates,
            &self.server_name,
            &mut self
                .server_cert
                .scts()
                .map(|sct| sct.as_slice())
                .unwrap_or(&[])
                .iter()
                .map(|sct| sct.0.as_slice()),
            self.server_cert.ocsp_response(),
            now,
        ) {
            Ok(cert_verified) => cert_verified,
            Err(e) => return Err(hs::send_cert_error_alert(cx, Error::CoreError(e)).await?),
        };

        // 2. Verify their signature on the handshake.
        let handshake_hash = self.transcript.get_current_hash();
        let sig_verified = match self.config.verifier.verify_tls13_signature(
            &verify::construct_tls13_server_verify_message(&handshake_hash),
            &self.server_cert.cert_chain()[0],
            cert_verify,
        ) {
            Ok(sig_verified) => sig_verified,
            Err(e) => return Err(hs::send_cert_error_alert(cx, Error::CoreError(e)).await?),
        };

        self.transcript.add_message(&m);

        Ok(Box::new(ExpectFinished {
            transcript: self.transcript,
            client_auth: self.client_auth,
            cert_verified,
            sig_verified,
        }))
    }
}

async fn emit_certificate_tls13(
    transcript: &mut HandshakeHash,
    certkey: Option<&CertifiedKey>,
    auth_context: Option<Vec<u8>>,
    common: &mut CommonState,
) -> Result<(), Error> {
    let context = auth_context.unwrap_or_default();

    let mut cert_payload = CertificatePayloadTLS13 {
        context: PayloadU8::new(context),
        entries: Vec::new(),
    };

    if let Some(certkey) = certkey {
        for cert in &certkey.cert {
            cert_payload
                .entries
                .push(CertificateEntry::new(cert.clone()));
        }
    }

    let m = Message {
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::Certificate,
            payload: HandshakePayload::CertificateTLS13(cert_payload),
        }),
    };
    transcript.add_message(&m);
    common.send_msg(m, true).await
}

async fn emit_certverify_tls13(
    transcript: &mut HandshakeHash,
    signer: &dyn Signer,
    common: &mut CommonState,
) -> Result<(), Error> {
    let message = verify::construct_tls13_client_verify_message(&transcript.get_current_hash());

    let scheme = signer.scheme();
    let sig = signer.sign(&message)?;
    let dss = DigitallySignedStruct::new(scheme, sig);

    let m = Message {
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::CertificateVerify,
            payload: HandshakePayload::CertificateVerify(dss),
        }),
    };

    transcript.add_message(&m);
    common.send_msg(m, true).await
}

async fn emit_finished_tls13(
    verify_data: &[u8],
    transcript: &mut HandshakeHash,
    common: &mut CommonState,
) -> Result<(), Error> {
    let verify_data_payload = Payload::new(verify_data);

    let m = Message {
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::Finished,
            payload: HandshakePayload::Finished(verify_data_payload),
        }),
    };

    transcript.add_message(&m);
    common.send_msg(m, true).await
}

struct ExpectFinished {
    transcript: HandshakeHash,
    client_auth: Option<ClientAuthDetails>,
    cert_verified: verify::ServerCertVerified,
    sig_verified: verify::HandshakeSignatureValid,
}

#[async_trait]
impl State for ExpectFinished {
    async fn handle(
        self: Box<Self>,
        cx: &mut CommonState,
        m: Message,
    ) -> hs::NextStateOrError {
        let mut st = *self;
        let finished =
            require_handshake_msg!(m, HandshakeType::Finished, HandshakePayload::Finished)?;

        let handshake_hash = st.transcript.get_current_hash();
        let expect_verify_data = cx
            .backend
            .get_server_finished_vd(handshake_hash.as_ref().to_vec())
            .await?;

        #[allow(deprecated)]
        let fin = match constant_time::verify_slices_are_equal(
            expect_verify_data.as_ref(),
            &finished.0,
        ) {
            Ok(()) => verify::FinishedMessageVerified::assertion(),
            Err(_) => {
                cx
                    .send_fatal_alert(AlertDescription::DecryptError)
                    .await?;
                return Err(Error::DecryptError);
            }
        };

        st.transcript.add_message(&m);

        /* Send our authentication/finished messages.  These are still encrypted
         * with our handshake keys. */
        if let Some(client_auth) = st.client_auth {
            match client_auth {
                ClientAuthDetails::Empty {
                    auth_context_tls13: auth_context,
                } => {
                    emit_certificate_tls13(&mut st.transcript, None, auth_context, cx)
                        .await?;
                }
                ClientAuthDetails::Verify {
                    certkey,
                    signer,
                    auth_context_tls13: auth_context,
                } => {
                    emit_certificate_tls13(
                        &mut st.transcript,
                        Some(&certkey),
                        auth_context,
                        cx,
                    )
                    .await?;
                    emit_certverify_tls13(&mut st.transcript, signer.as_ref(), cx).await?;
                }
            }
        }

        let handshake_hash = st.transcript.get_current_hash();
        let client_finished = cx
            .backend
            .get_client_finished_vd(handshake_hash.as_ref().to_vec())
            .await?;
        emit_finished_tls13(&client_finished, &mut st.transcript, cx).await?;

        /* Now move to our application traffic keys. */
        cx.check_aligned_handshake().await?;

        // Switching to the application traffic keys is not supported by the
        // MPC backend.
        unsupported()?;

        cx.start_traffic().await?;

        let st = ExpectTraffic {
            _cert_verified: st.cert_verified,
            _sig_verified: st.sig_verified,
            _fin_verified: fin,
        };

        Ok(Box::new(st))
    }
}

// -- Traffic transit state (TLS1.3) --
// In this state we can be sent tickets, key updates,
// and application data.
struct ExpectTraffic {
    _cert_verified: verify::ServerCertVerified,
    _sig_verified: verify::HandshakeSignatureValid,
    _fin_verified: verify::FinishedMessageVerified,
}

impl ExpectTraffic {
    #[allow(clippy::unnecessary_wraps)]
    async fn handle_new_ticket_tls13(
        &mut self,
        cx: &mut CommonState,
        nst: &NewSessionTicketPayloadTLS13,
    ) -> Result<(), Error> {
        if nst.has_duplicate_extension() {
            cx
                .send_fatal_alert(AlertDescription::IllegalParameter)
                .await?;
            return Err(Error::PeerMisbehavedError(
                "peer sent duplicate NewSessionTicket extensions".into(),
            ));
        }

        Ok(())
    }

    async fn handle_key_update(
        &mut self,
        common: &mut CommonState,
        _kur: &KeyUpdateRequest,
    ) -> Result<(), Error> {
        // Mustn't be interleaved with other handshake messages.
        common.check_aligned_handshake().await?;

        // Client does not support key updates
        common
            .send_fatal_alert(AlertDescription::InternalError)
            .await?;

        Err(Error::General(
            "received unsupported key update request from peer".to_string(),
        ))
    }
}

#[async_trait]
impl State for ExpectTraffic {
    async fn handle(
        mut self: Box<Self>,
        cx: &mut CommonState,
        m: Message,
    ) -> hs::NextStateOrError {
        match m.payload {
            MessagePayload::ApplicationData(payload) => cx.take_received_plaintext(payload),
            MessagePayload::Handshake(HandshakeMessagePayload {
                payload: HandshakePayload::NewSessionTicketTLS13(ref new_ticket),
                ..
            }) => self.handle_new_ticket_tls13(cx, new_ticket).await?,
            MessagePayload::Handshake(HandshakeMessagePayload {
                payload: HandshakePayload::KeyUpdate(ref key_update),
                ..
            }) => self.handle_key_update(cx, key_update).await?,
            payload => {
                return Err(inappropriate_handshake_message(
                    &payload,
                    &[ContentType::ApplicationData, ContentType::Handshake],
                    &[HandshakeType::NewSessionTicket, HandshakeType::KeyUpdate],
                ));
            }
        }

        Ok(self)
    }
}
