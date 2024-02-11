use std::{collections::HashMap, sync::Arc};

use async_rustls::TlsAcceptor;
use axum::{
    extract::Query,
    response::{Html, Json},
    routing::get,
    Router,
};
use futures::{AsyncRead, AsyncWrite};
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

fn app() -> Router {
    Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .route("/bytes", get(bytes))
        .route("/formats/json", get(json))
        .route("/formats/html", get(html))
}

/// Bind the server to the given socket.
pub async fn bind<T: AsyncRead + AsyncWrite + Send + Unpin + 'static>(socket: T) {
    let key = PrivateKey(SERVER_KEY_DER.to_vec());
    let cert = Certificate(SERVER_CERT_DER.to_vec());

    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();

    let acceptor = TlsAcceptor::from(Arc::new(config));

    let conn = acceptor.accept(socket).await.unwrap();

    Http::new()
        .http1_only(true)
        .http1_keep_alive(false)
        .serve_connection(conn.compat(), app())
        .await
        .unwrap();
}

async fn bytes(Query(params): Query<HashMap<String, String>>) -> Result<Bytes, StatusCode> {
    let size = params
        .get("size")
        .and_then(|size| size.parse::<usize>().ok())
        .unwrap_or(1);

    Ok(Bytes::from(vec![0x42u8; size]))
}

async fn json(
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<&'static str>, StatusCode> {
    let size = params
        .get("size")
        .and_then(|size| size.parse::<usize>().ok())
        .unwrap_or(1);

    match size {
        1 => Ok(Json(include_str!("data/1kb.json"))),
        4 => Ok(Json(include_str!("data/4kb.json"))),
        8 => Ok(Json(include_str!("data/8kb.json"))),
        _ => Err(StatusCode::NOT_FOUND),
    }
}

async fn html() -> Html<&'static str> {
    Html(include_str!("data/4kb.html"))
}
