use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use async_rustls::TlsAcceptor;
use axum::{
    extract::{Query, State},
    response::{Html, Json},
    routing::get,
    Router,
};
use futures::{channel::oneshot, AsyncRead, AsyncWrite};
use hyper::{body::Bytes, server::conn::Http, StatusCode};
use rustls::{Certificate, PrivateKey, ServerConfig};

use tokio_util::compat::FuturesAsyncReadCompatExt;

/// A certificate authority certificate fixture.
pub static CA_CERT_DER: &[u8] = include_bytes!("tls/rootCA.der");
/// A server certificate (domain=test-server.io) fixture.
pub static SERVER_CERT_DER: &[u8] = include_bytes!("tls/domain.der");
/// A server private key fixture.
pub static SERVER_KEY_DER: &[u8] = include_bytes!("tls/domain_key.der");
/// The domain name bound to the server certificate.
pub static SERVER_DOMAIN: &str = "test-server.io";

struct AppState {
    shutdown: Option<oneshot::Sender<()>>,
}

fn app(state: AppState) -> Router {
    Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .route("/bytes", get(bytes))
        .route("/formats/json", get(json))
        .route("/formats/html", get(html))
        .with_state(Arc::new(Mutex::new(state)))
}

/// Bind the server to the given socket.
pub async fn bind<T: AsyncRead + AsyncWrite + Send + Unpin + 'static>(
    socket: T,
) -> anyhow::Result<()> {
    let key = PrivateKey(SERVER_KEY_DER.to_vec());
    let cert = Certificate(SERVER_CERT_DER.to_vec());

    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();

    let acceptor = TlsAcceptor::from(Arc::new(config));

    let conn = acceptor.accept(socket).await?;

    let (sender, receiver) = oneshot::channel();
    let state = AppState {
        shutdown: Some(sender),
    };

    tokio::select! {
        _ = Http::new()
            .http1_only(true)
            .http1_keep_alive(false)
            .serve_connection(conn.compat(), app(state)) => {},
        _ = receiver => {},
    }

    Ok(())
}

async fn bytes(
    State(state): State<Arc<Mutex<AppState>>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Bytes, StatusCode> {
    let size = params
        .get("size")
        .and_then(|size| size.parse::<usize>().ok())
        .unwrap_or(1);

    if params.get("shutdown").is_some() {
        _ = state.lock().unwrap().shutdown.take().unwrap().send(());
    }

    Ok(Bytes::from(vec![0x42u8; size]))
}

async fn json(
    State(state): State<Arc<Mutex<AppState>>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<&'static str>, StatusCode> {
    let size = params
        .get("size")
        .and_then(|size| size.parse::<usize>().ok())
        .unwrap_or(1);

    if params.get("shutdown").is_some() {
        _ = state.lock().unwrap().shutdown.take().unwrap().send(());
    }

    match size {
        1 => Ok(Json(include_str!("data/1kb.json"))),
        4 => Ok(Json(include_str!("data/4kb.json"))),
        8 => Ok(Json(include_str!("data/8kb.json"))),
        _ => Err(StatusCode::NOT_FOUND),
    }
}

async fn html(
    State(state): State<Arc<Mutex<AppState>>>,
    Query(params): Query<HashMap<String, String>>,
) -> Html<&'static str> {
    if params.get("shutdown").is_some() {
        _ = state.lock().unwrap().shutdown.take().unwrap().send(());
    }

    Html(include_str!("data/4kb.html"))
}
