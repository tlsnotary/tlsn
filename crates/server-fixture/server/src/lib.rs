use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use axum::{
    extract::{Query, State},
    response::{Html, Json},
    routing::get,
    Router,
};
use futures::{channel::oneshot, AsyncRead, AsyncWrite};
use futures_rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    rustls::ServerConfig,
    TlsAcceptor,
};
use hyper::{
    body::{Bytes, Incoming},
    server::conn::http1,
    Request, StatusCode,
};
use hyper_util::rt::TokioIo;

use tokio_util::compat::FuturesAsyncReadCompatExt;
use tower_service::Service;

use tlsn_server_fixture_certs::*;

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
    let key = PrivateKeyDer::Pkcs8(SERVER_KEY_DER.into());
    let cert = CertificateDer::from(SERVER_CERT_DER);

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();

    let acceptor = TlsAcceptor::from(Arc::new(config));

    let conn = acceptor.accept(socket).await?;

    let io = TokioIo::new(conn.compat());

    let (sender, receiver) = oneshot::channel();
    let state = AppState {
        shutdown: Some(sender),
    };
    let tower_service = app(state);

    let hyper_service = hyper::service::service_fn(move |request: Request<Incoming>| {
        tower_service.clone().call(request)
    });

    tokio::select! {
        _ = http1::Builder::new()
                .keep_alive(false)
                .serve_connection(io, hyper_service) => {},
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

    if params.contains_key("shutdown") {
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

    if params.contains_key("shutdown") {
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
    if params.contains_key("shutdown") {
        _ = state.lock().unwrap().shutdown.take().unwrap().send(());
    }

    Html(include_str!("data/4kb.html"))
}
