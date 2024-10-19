pub mod axum_websocket;
pub mod tcp;
pub mod websocket;

use std::sync::Arc;

use async_trait::async_trait;
use axum::{
    extract::{rejection::JsonRejection, FromRequestParts, Query, State},
    http::{header, request::Parts, StatusCode},
    response::{IntoResponse, Json, Response},
};
use axum_macros::debug_handler;
use tlsn_common::config::ProtocolConfigValidator;
use tlsn_core::{attestation::AttestationConfig, CryptoProvider};
use tlsn_verifier::{Verifier, VerifierConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::{debug, error, info, trace};
use uuid::Uuid;

use crate::{
    domain::notary::{
        NotarizationRequestQuery, NotarizationSessionRequest, NotarizationSessionResponse,
        NotaryGlobals,
    },
    error::NotaryServerError,
    service::{
        axum_websocket::{header_eq, WebSocketUpgrade},
        tcp::{tcp_notarize, TcpUpgrade},
        websocket::websocket_notarize,
    },
};

/// A wrapper enum to facilitate extracting TCP connection for either WebSocket
/// or TCP clients, so that we can use a single endpoint and handler for
/// notarization for both types of clients
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

/// Handler to upgrade protocol from http to either websocket or underlying tcp
/// depending on the type of client the session_id parameter is also extracted
/// here to fetch the configuration parameters that have been submitted in the
/// previous request to /session made by the same client
pub async fn upgrade_protocol(
    protocol_upgrade: ProtocolUpgrade,
    State(notary_globals): State<NotaryGlobals>,
    Query(params): Query<NotarizationRequestQuery>,
) -> Response {
    info!("Received upgrade protocol request");
    let session_id = params.session_id;
    // Check if session_id exists in the store, this also removes session_id from
    // the store as each session_id can only be used once
    if notary_globals
        .store
        .lock()
        .unwrap()
        .remove(&session_id)
        .is_none()
    {
        let err_msg = format!("Session id {} does not exist", session_id);
        error!(err_msg);
        return NotaryServerError::BadProverRequest(err_msg).into_response();
    };
    // This completes the HTTP Upgrade request and returns a successful response to
    // the client, meanwhile initiating the websocket or tcp connection
    match protocol_upgrade {
        ProtocolUpgrade::Ws(ws) => {
            ws.on_upgrade(move |socket| websocket_notarize(socket, notary_globals, session_id))
        }
        ProtocolUpgrade::Tcp(tcp) => {
            tcp.on_upgrade(move |stream| tcp_notarize(stream, notary_globals, session_id))
        }
    }
}

/// Handler to initialize and configure notarization for both TCP and WebSocket
/// clients
#[debug_handler(state = NotaryGlobals)]
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

    // Ensure that the max_sent_data, max_recv_data submitted is not larger than the
    // global max limits configured in notary server
    if payload.max_sent_data.is_some() || payload.max_recv_data.is_some() {
        if payload.max_sent_data.unwrap_or_default()
            > notary_globals.notarization_config.max_sent_data
        {
            error!(
                "Max sent data requested {:?} exceeds the global maximum threshold {:?}",
                payload.max_sent_data.unwrap_or_default(),
                notary_globals.notarization_config.max_sent_data
            );
            return NotaryServerError::BadProverRequest(
                "Max sent data requested exceeds the global maximum threshold".to_string(),
            )
            .into_response();
        }
        if payload.max_recv_data.unwrap_or_default()
            > notary_globals.notarization_config.max_recv_data
        {
            error!(
                "Max recv data requested {:?} exceeds the global maximum threshold {:?}",
                payload.max_recv_data.unwrap_or_default(),
                notary_globals.notarization_config.max_recv_data
            );
            return NotaryServerError::BadProverRequest(
                "Max recv data requested exceeds the global maximum threshold".to_string(),
            )
            .into_response();
        }
    }

    let prover_session_id = Uuid::new_v4().to_string();

    // Store the configuration data in a temporary store
    notary_globals
        .store
        .lock()
        .unwrap()
        .insert(prover_session_id.clone(), ());

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

/// Run the notarization
pub async fn notary_service<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
    socket: T,
    crypto_provider: Arc<CryptoProvider>,
    session_id: &str,
    max_sent_data: usize,
    max_recv_data: usize,
) -> Result<(), NotaryServerError> {
    debug!(?session_id, "Starting notarization...");

    let att_config = AttestationConfig::builder()
        .supported_signature_algs(Vec::from_iter(crypto_provider.signer.supported_algs()))
        .build()
        .map_err(|err| NotaryServerError::Notarization(Box::new(err)))?;

    let config = VerifierConfig::builder()
        .protocol_config_validator(
            ProtocolConfigValidator::builder()
                .max_sent_data(max_sent_data)
                .max_recv_data(max_recv_data)
                .build()?,
        )
        .crypto_provider(crypto_provider)
        .build()?;

    Verifier::new(config)
        .notarize(socket.compat(), &att_config)
        .await?;

    Ok(())
}
