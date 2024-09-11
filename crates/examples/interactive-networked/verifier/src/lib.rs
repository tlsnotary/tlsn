use axum::{
    extract::{Request, State},
    response::IntoResponse,
    routing::get,
    Router,
};
use axum_websocket::{WebSocket, WebSocketUpgrade};
use eyre::eyre;
use hyper::{body::Incoming, server::conn::http1};
use hyper_util::rt::TokioIo;
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tlsn_core::proof::SessionInfo;
use tlsn_verifier::tls::{Verifier, VerifierConfig};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tower_service::Service;
use tracing::{debug, error, info};
use ws_stream_tungstenite::WsStream;

mod axum_websocket;

/// Global data that needs to be shared with the axum handlers
#[derive(Clone, Debug)]
struct VerifierGlobals {
    pub server_domain: String,
    pub verification_session_id: String,
}

pub async fn run_server(
    verifier_host: &str,
    verifier_port: u16,
    server_domain: &str,
    verification_session_id: &str,
) -> Result<(), eyre::ErrReport> {
    let verifier_address = SocketAddr::new(
        IpAddr::V4(verifier_host.parse().map_err(|err| {
            eyre!("Failed to parse verifer host address from server config: {err}")
        })?),
        verifier_port,
    );
    let listener = TcpListener::bind(verifier_address)
        .await
        .map_err(|err| eyre!("Failed to bind server address to tcp listener: {err}"))?;

    info!("Listening for TCP traffic at {}", verifier_address);

    let protocol = Arc::new(http1::Builder::new());
    let router = Router::new()
        .route("/verify", get(ws_handler))
        .with_state(VerifierGlobals {
            server_domain: server_domain.to_string(),
            verification_session_id: verification_session_id.to_string(),
        });

    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(err) => {
                error!("Failed to connect to prover: {err}");
                continue;
            }
        };
        debug!("Received a prover's TCP connection");

        let tower_service = router.clone();
        let protocol = protocol.clone();

        tokio::spawn(async move {
            info!("Accepted prover's TCP connection",);
            // Reference: https://github.com/tokio-rs/axum/blob/5201798d4e4d4759c208ef83e30ce85820c07baa/examples/low-level-rustls/src/main.rs#L67-L80
            let io = TokioIo::new(stream);
            let hyper_service = hyper::service::service_fn(move |request: Request<Incoming>| {
                tower_service.clone().call(request)
            });
            // Serve different requests using the same hyper protocol and axum router
            let _ = protocol
                .serve_connection(io, hyper_service)
                // use with_upgrades to upgrade connection to websocket for websocket clients
                // and to extract tcp connection for tcp clients
                .with_upgrades()
                .await;
        });
    }
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(verifier_globals): State<VerifierGlobals>,
) -> impl IntoResponse {
    info!("Received websocket request");
    ws.on_upgrade(|socket| handle_socket(socket, verifier_globals))
}

async fn handle_socket(socket: WebSocket, verifier_globals: VerifierGlobals) {
    debug!("Upgraded to websocket connection");
    let stream = WsStream::new(socket.into_inner());

    match verifier(
        stream,
        &verifier_globals.verification_session_id,
        &verifier_globals.server_domain,
    )
    .await
    {
        Ok((sent, received, _session_info)) => {
            info!("Successfully verified {}", &verifier_globals.server_domain);
            info!("Verified sent data:\n{}", sent,);
            println!("Verified received data:\n{}", received,);
        }
        Err(err) => {
            error!("Failed verification using websocket: {err}");
        }
    }
}

async fn verifier<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
    socket: T,
    verification_session_id: &str,
    server_domain: &str,
) -> Result<(String, String, SessionInfo), eyre::ErrReport> {
    debug!("Starting verification...");

    // Setup Verifier.
    let verifier_config = VerifierConfig::builder()
        .id(verification_session_id)
        .build()?;
    let verifier = Verifier::new(verifier_config);

    // Verify MPC-TLS and wait for (redacted) data.
    debug!("Starting MPC-TLS verification...");
    let (sent, received, session_info) = verifier
        .verify(socket.compat())
        .await
        .map_err(|err| eyre!("Verification failed: {err}"))?;

    // Check sent data: check host.
    debug!("Starting sent data verification...");
    let sent_data = String::from_utf8(sent.data().to_vec())
        .map_err(|err| eyre!("Failed to parse sent data: {err}"))?;
    sent_data
        .find(server_domain)
        .ok_or_else(|| eyre!("Verification failed: Expected host {}", server_domain))?;

    // Check received data: check json and version number.
    debug!("Starting received data verification...");
    let response = String::from_utf8(received.data().to_vec())
        .map_err(|err| eyre!("Failed to parse received data: {err}"))?;
    debug!("Received data: {:?}", response);
    response
        .find("eye_color")
        .ok_or_else(|| eyre!("Verification failed: missing eye_color in received data"))?;
    // Check Session info: server name.
    if session_info.server_name.as_str() != server_domain {
        return Err(eyre!("Verification failed: server name mismatches"));
    }

    let sent_string = bytes_to_redacted_string(sent.data())?;
    let received_string = bytes_to_redacted_string(received.data())?;

    Ok((sent_string, received_string, session_info))
}

/// Render redacted bytes as `🙈`.
fn bytes_to_redacted_string(bytes: &[u8]) -> Result<String, eyre::ErrReport> {
    Ok(String::from_utf8(bytes.to_vec())
        .map_err(|err| eyre!("Failed to parse bytes to redacted string: {err}"))?
        .replace('\0', "🙈"))
}
