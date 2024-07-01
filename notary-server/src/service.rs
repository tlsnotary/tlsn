pub mod axum_websocket;
pub mod tcp;
pub mod websocket;

use async_trait::async_trait;
use axum::{
    extract::{rejection::JsonRejection, FromRequestParts, Query, State},
    http::{header, request::Parts, StatusCode},
    response::{IntoResponse, Json, Response},
    Error,
};
use axum_macros::debug_handler;
use chrono::Utc;
use p256::ecdsa::{Signature, SigningKey};
use tlsn_verifier::tls::{Verifier, VerifierConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::{debug, error, info, trace};
use uuid::Uuid;

use crate::{
    domain::notary::{
        NotarizationRequestQuery, NotarizationSessionRequest, NotarizationSessionResponse,
        NotaryGlobals, SessionData, TLSProof, VerificationRequest,
    },
    error::NotaryServerError,
    service::{
        axum_websocket::{header_eq, WebSocketUpgrade},
        tcp::{tcp_notarize, TcpUpgrade},
        websocket::{websocket_notarize, websocket_verify},
    },
};

/// A wrapper enum to facilitate extracting TCP connection for either WebSocket or TCP clients,
/// so that we can use a single endpoint and handler for notarization for both types of clients
pub enum ProtocolUpgrade {
    Tcp(TcpUpgrade),
    Ws(WebSocketUpgrade),
}

#[async_trait]
impl<S> FromRequestParts<S> for ProtocolUpgrade
where
    S: Send + Sync,
{
    type Rejection = NotaryServerError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // Extract tcp connection for websocket client
        if header_eq(&parts.headers, header::UPGRADE, "websocket") {
            let extractor = WebSocketUpgrade::from_request_parts(parts, state)
                .await
                .map_err(|err| NotaryServerError::BadProverRequest(err.to_string()))?;
            return Ok(Self::Ws(extractor));
        // Extract tcp connection for tcp client
        } else if header_eq(&parts.headers, header::UPGRADE, "tcp") {
            let extractor = TcpUpgrade::from_request_parts(parts, state)
                .await
                .map_err(|err| NotaryServerError::BadProverRequest(err.to_string()))?;
            return Ok(Self::Tcp(extractor));
        } else {
            return Err(NotaryServerError::BadProverRequest(
                "Upgrade header is not set for client".to_string(),
            ));
        }
    }
}

/// Handler to upgrade protocol from http to either websocket or underlying tcp depending on the type of client
/// the session_id parameter is also extracted here to fetch the configuration parameters
/// that have been submitted in the previous request to /session made by the same client
pub async fn upgrade_protocol(
    protocol_upgrade: ProtocolUpgrade,
    State(notary_globals): State<NotaryGlobals>,
    Query(params): Query<NotarizationRequestQuery>,
) -> Response {
    info!("Received upgrade protocol request");
    let session_id = params.session_id;
    // Fetch the configuration data from the store using the session_id
    // This also removes the configuration data from the store as each session_id can only be used once
    let (max_sent_data, max_recv_data) = match notary_globals.store.lock().await.remove(&session_id)
    {
        Some(data) => (data.max_sent_data, data.max_recv_data),
        None => {
            let err_msg = format!("Session id {} does not exist", session_id);
            error!(err_msg);
            return NotaryServerError::BadProverRequest(err_msg).into_response();
        }
    };
    // This completes the HTTP Upgrade request and returns a successful response to the client, meanwhile initiating the websocket or tcp connection
    match protocol_upgrade {
        ProtocolUpgrade::Ws(ws) => ws.on_upgrade(move |socket| {
            websocket_notarize(
                socket,
                notary_globals,
                session_id,
                max_sent_data,
                max_recv_data,
            )
        }),
        ProtocolUpgrade::Tcp(tcp) => tcp.on_upgrade(move |stream| {
            tcp_notarize(
                stream,
                notary_globals,
                session_id,
                max_sent_data,
                max_recv_data,
            )
        }),
    }
}

pub async fn initialize(
    State(notary_globals): State<NotaryGlobals>,
    payload: Result<Json<NotarizationSessionRequest>, JsonRejection>,
) -> impl IntoResponse {
    info!(
        ?payload,
        "Received request for initializing a notarization session"
    );

    // Parse the body payload
    let payload = match payload {
        Ok(payload) => payload,
        Err(err) => {
            error!("Malformed payload submitted for initializing notarization: {err}");
            return NotaryServerError::BadProverRequest(err.to_string()).into_response();
        }
    };

    // Ensure that the max_transcript_size submitted is not larger than the global max limit configured in notary server
    if payload.max_sent_data.is_some() || payload.max_recv_data.is_some() {
        let requested_transcript_size =
            payload.max_sent_data.unwrap_or_default() + payload.max_recv_data.unwrap_or_default();
        if requested_transcript_size > notary_globals.notarization_config.max_transcript_size {
            error!(
                "Max transcript size requested {:?} exceeds the maximum threshold {:?}",
                requested_transcript_size, notary_globals.notarization_config.max_transcript_size
            );
            return NotaryServerError::BadProverRequest(
                "Max transcript size requested exceeds the maximum threshold".to_string(),
            )
            .into_response();
        }
    }

    let prover_session_id = Uuid::new_v4().to_string();

    // Store the configuration data in a temporary store
    notary_globals.store.lock().await.insert(
        prover_session_id.clone(),
        SessionData {
            max_sent_data: payload.max_sent_data,
            max_recv_data: payload.max_recv_data,
            created_at: Utc::now(),
        },
    );

    trace!("Latest store state: {:?}", notary_globals.store);

    // Return the session id in the response to the client
    (
        StatusCode::OK,
        Json(NotarizationSessionResponse {
            session_id: prover_session_id,
        }),
    )
        .into_response()
}

use tlsn_core::proof::{SessionProof, SubstringsProof, TlsProof};
/// Handler to verify the TLS proof and sign it with EDDSA
#[debug_handler(state = NotaryGlobals)]
pub async fn verify_proof(
    State(notary_globals): State<NotaryGlobals>,
    payload: Result<Json<TlsProof>, JsonRejection>,
) -> impl IntoResponse {
    info!(?payload, "Received request for verifying TLS proof");

    // Parse the body payload and extract TLSProof
    let payload: TlsProof = match payload {
        Ok(Json(payload)) => payload,
        Err(err) => {
            error!("Malformed payload submitted for initializing notarization: {err}");
            return NotaryServerError::BadProverRequest(err.to_string()).into_response();
        }
    };

    info!("payload: {:#?}", payload);

    let notary_pubkey = hex::encode(notary_globals.notary_signing_key.to_bytes());

    _ = verify(payload, &notary_pubkey).await;

    // Return a JSON with field success = "OK" in the response to the client
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "success": "OK"
        })),
    )
        .into_response()
}
use std::time::Duration;
pub async fn verify(proof: TlsProof, notary_pubkey_str: &str) -> Result<String, Error> {
    let TlsProof {
        // The session proof establishes the identity of the server and the commitments
        // to the TLS transcript.
        session,
        // The substrings proof proves select portions of the transcript, while redacting
        // anything the Prover chose not to disclose.
        substrings,
    } = proof;

    info!(
        "!@# notary_pubkey {}, {}",
        notary_pubkey_str,
        notary_pubkey_str.len()
    );
    // session
    //     .verify_with_default_cert_verifier(get_notary_pubkey(notary_pubkey_str)?)
    //     .map_err(|e| &format!("Session verification failed: {:?}", e))?;

    let SessionProof {
        // The session header that was signed by the Notary is a succinct commitment to the TLS transcript.
        header,
        // This is the server name, checked against the certificate chain shared in the TLS handshake.
        session_info,
        ..
    } = session;

    // The time at which the session was recorded
    let time = chrono::DateTime::UNIX_EPOCH + Duration::from_secs(header.time());

    // Verify the substrings proof against the session header.
    //
    // This returns the redacted transcripts
    let (mut sent, mut recv) = substrings.verify(&header).unwrap();
    // Replace the bytes which the Prover chose not to disclose with 'X'
    sent.set_redacted(b'X');
    recv.set_redacted(b'X');

    info!("-------------------------------------------------------------------");
    info!(
        "Successfully verified that the bytes below came from a session with {:?} at {}.",
        session_info.server_name, time
    );
    info!("Note that the bytes which the Prover chose not to disclose are shown as X.");
    info!("Bytes sent:");
    info!(
        "{}",
        String::from_utf8(sent.data().to_vec())
            .unwrap_or("Could not convert sent data to string".to_string())
    );
    info!("Bytes received:");
    info!(
        "{}",
        String::from_utf8(recv.data().to_vec())
            .unwrap_or("Could not convert recv data to string".to_string())
    );
    info!("-------------------------------------------------------------------");

    #[derive(serde::Serialize, serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct VerifyResult {
        pub server_name: String,
        pub time: u64,
        pub sent: String,
        pub recv: String,
    }

    let result = VerifyResult {
        server_name: String::from(session_info.server_name.as_str()),
        time: header.time(),
        sent: String::from_utf8(sent.data().to_vec())
            .unwrap_or("Could not convert sent data to string".to_string()),
        recv: String::from_utf8(recv.data().to_vec())
            .unwrap_or("Could not convert recv data to string".to_string()),
    };
    let res =
        serde_json::to_string_pretty(&result).unwrap_or("Could not serialize result".to_string());

    Ok(res)
}

/// Run the notarization
pub async fn notary_service<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
    socket: T,
    signing_key: &SigningKey,
    session_id: &str,
    max_sent_data: Option<usize>,
    max_recv_data: Option<usize>,
) -> Result<(), NotaryServerError> {
    debug!(?session_id, "Starting notarization...");

    let mut config_builder = VerifierConfig::builder();

    config_builder = config_builder.id(session_id);

    debug!("config_builder.max_sent_data {:?}", max_sent_data);

    if let Some(max_sent_data) = max_sent_data {
        config_builder = config_builder.max_sent_data(max_sent_data);
    }

    if let Some(max_recv_data) = max_recv_data {
        config_builder = config_builder.max_recv_data(max_recv_data);
    }

    debug!("config_builder.build");

    let config = config_builder.build()?;

    debug!("Verifier::new");

    let verifier = Verifier::new(config);

    verifier
        .notarize::<_, Signature>(socket.compat(), signing_key)
        .await?;

    Ok(())
}

/// Run the notarization
pub async fn verify_service<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
    socket: T,
    _: &SigningKey,
    session_id: &str,
) -> Result<(), NotaryServerError> {
    debug!(?session_id, "Starting verification...");

    let mut config_builder = VerifierConfig::builder();

    config_builder = config_builder.id(session_id);

    debug!("config_builder.build");

    let config = config_builder.build()?;

    debug!("Verifier::new");

    let verifier = Verifier::new(config);

    // Verify MPC-TLS and wait for (redacted) data.
    //let (sent, received, session_info) = verifier.verify(socket.compat()).await.unwrap();

    info!("Verification successful");
    // info!("{:#?}", session_info);
    // info!("{:#?}", sent);
    // info!("{:#?}", received);

    Ok(())
}
