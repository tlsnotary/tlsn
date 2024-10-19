use tracing::{debug, error, info};
use ws_stream_tungstenite::WsStream;

use crate::{
    domain::notary::NotaryGlobals,
    service::{axum_websocket::WebSocket, notary_service},
};

/// Perform notarization using the established websocket connection
pub async fn websocket_notarize(
    socket: WebSocket,
    notary_globals: NotaryGlobals,
    session_id: String,
) {
    debug!(?session_id, "Upgraded to websocket connection");
    // Wrap the websocket in WsStream so that we have AsyncRead and AsyncWrite
    // implemented
    let stream = WsStream::new(socket.into_inner());
    match notary_service(
        stream,
        notary_globals.crypto_provider.clone(),
        &session_id,
        notary_globals.notarization_config.max_sent_data,
        notary_globals.notarization_config.max_recv_data,
    )
    .await
    {
        Ok(_) => {
            info!(?session_id, "Successful notarization using websocket!");
        }
        Err(err) => {
            error!(?session_id, "Failed notarization using websocket: {err}");
        }
    }
}
