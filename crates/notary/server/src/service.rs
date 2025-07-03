pub mod axum_websocket;
pub mod tcp;
pub mod websocket;

use axum::{
    body::Body,
    extract::{rejection::JsonRejection, FromRequestParts, Query, State},
    http::{header, request::Parts, StatusCode},
    response::{IntoResponse, Json, Response},
};
use axum_macros::debug_handler;
use eyre::eyre;
use notary_common::{NotarizationSessionRequest, NotarizationSessionResponse};
use std::time::Duration;
use tlsn::{
    attestation::AttestationConfig,
    config::ProtocolConfigValidator,
    verifier::{Verifier, VerifierConfig},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    time::timeout,
};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::{debug, error, info, trace};
use uuid::Uuid;

use crate::{
    error::NotaryServerError,
    service::{
        axum_websocket::{header_eq, WebSocketUpgrade},
        tcp::{tcp_notarize, TcpUpgrade},
        websocket::websocket_notarize,
    },
    types::{NotarizationRequestQuery, NotaryGlobals},
};

/// A wrapper enum to facilitate extracting TCP connection for either WebSocket
/// or TCP clients, so that we can use a single endpoint and handler for
/// notarization for both types of clients
pub enum ProtocolUpgrade {
    Tcp(TcpUpgrade),
    Ws(WebSocketUpgrade),
}

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
            Ok(Self::Ws(extractor))
        // Extract tcp connection for tcp client
        } else if header_eq(&parts.headers, header::UPGRADE, "tcp") {
            let extractor = TcpUpgrade::from_request_parts(parts, state)
                .await
                .map_err(|err| NotaryServerError::BadProverRequest(err.to_string()))?;
            Ok(Self::Tcp(extractor))
        } else {
            Err(NotaryServerError::BadProverRequest(
                "Upgrade header is not set for client".to_string(),
            ))
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
    let permit = if let Ok(permit) = notary_globals.semaphore.clone().try_acquire_owned() {
        permit
    } else {
        // TODO: estimate the time more precisely to avoid unnecessary retries.
        return Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .header("Retry-After", 5)
            .body(Body::default())
            .expect("Builder should not fail");
    };

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
        let err_msg = format!("Session id {session_id} does not exist");
        error!(err_msg);
        return NotaryServerError::BadProverRequest(err_msg).into_response();
    };
    // This completes the HTTP Upgrade request and returns a successful response to
    // the client, meanwhile initiating the websocket or tcp connection
    match protocol_upgrade {
        ProtocolUpgrade::Ws(ws) => ws.on_upgrade(move |socket| async move {
            websocket_notarize(socket, notary_globals, session_id).await;
            drop(permit);
        }),
        ProtocolUpgrade::Tcp(tcp) => tcp.on_upgrade(move |stream| async move {
            tcp_notarize(stream, notary_globals, session_id).await;
            drop(permit);
        }),
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
    notary_globals: NotaryGlobals,
    session_id: &str,
) -> Result<(), NotaryServerError> {
    debug!(?session_id, "Starting notarization...");

    let crypto_provider = notary_globals.crypto_provider.clone();

    let mut att_config_builder = AttestationConfig::builder();
    att_config_builder
        .supported_signature_algs(Vec::from_iter(crypto_provider.signer.supported_algs()));

    // If enabled, accepts any custom extensions from the prover.
    if notary_globals.notarization_config.allow_extensions {
        att_config_builder.extension_validator(|_| Ok(()));
    }

    let att_config = att_config_builder
        .build()
        .map_err(|err| NotaryServerError::Notarization(Box::new(err)))?;

    let config = VerifierConfig::builder()
        .protocol_config_validator(
            ProtocolConfigValidator::builder()
                .max_sent_data(notary_globals.notarization_config.max_sent_data)
                .max_recv_data(notary_globals.notarization_config.max_recv_data)
                .build()?,
        )
        .build()?;

    #[allow(deprecated)]
    timeout(
        Duration::from_secs(notary_globals.notarization_config.timeout),
        Verifier::new(config).notarize_with_provider(
            socket.compat(),
            &att_config,
            &crypto_provider,
        ),
    )
    .await
    .map_err(|_| eyre!("Timeout reached before notarization completes"))??;

    Ok(())
}
