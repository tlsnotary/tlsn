use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use axum::{
    extract::{Query, State},
    response::Html,
    routing::get,
    Json, Router,
};
use tower_http::trace::TraceLayer;

use futures::{channel::oneshot, AsyncRead, AsyncWrite};
use futures_rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    rustls::{crypto::aws_lc_rs::default_provider, server::WebPkiClientVerifier, RootCertStore, ServerConfig},
    TlsAcceptor,
};
use hyper::{
    body::{Bytes, Incoming},
    server::conn::http1,
    Request, StatusCode,
};
use hyper_util::rt::TokioIo;

use serde_json::Value;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tower_service::Service;

use axum::extract::FromRequest;
use hyper::header;

use tlsn_server_fixture_certs::*;
use tracing::info;

pub const DEFAULT_FIXTURE_PORT: u16 = 3000;

struct AppState {
    shutdown: Option<oneshot::Sender<()>>,
}

fn app(state: AppState) -> Router {
    Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .route("/bytes", get(bytes))
        .route("/formats/json", get(json))
        .route("/formats/html", get(html))
        .route("/protected", get(protected_route))
        .layer(TraceLayer::new_for_http())
        .with_state(Arc::new(Mutex::new(state)))
}

/// Bind the server to the given socket.
pub async fn bind<T: AsyncRead + AsyncWrite + Send + Unpin + 'static>(
    socket: T,
) -> anyhow::Result<()> {
    // Need to do this as notary server's dependency (ureq used by extism) uses ring
    // as rustls crypto provider.
    let _ = default_provider().install_default();

    let key = PrivateKeyDer::Pkcs8(SERVER_KEY_DER.into());
    let cert = CertificateDer::from(SERVER_CERT_DER);

    // Set up a client certificate verifier.
    let mut root_store = RootCertStore::empty();
    root_store.add(CA_CERT_DER.into()).unwrap();
    let client_cert_verifier = WebPkiClientVerifier::builder(root_store.into())
        .allow_unauthenticated()
        .build()
        .unwrap();

    let config = ServerConfig::builder()
        .with_client_cert_verifier(client_cert_verifier)
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
    info!("Handling /bytes with params: {:?}", params);

    let size = params
        .get("size")
        .and_then(|size| size.parse::<usize>().ok())
        .unwrap_or(1);

    if params.contains_key("shutdown") {
        _ = state.lock().unwrap().shutdown.take().unwrap().send(());
    }

    Ok(Bytes::from(vec![0x42u8; size]))
}

/// parse the JSON data from the file content
fn get_json_value(filecontent: &str) -> Result<Json<Value>, StatusCode> {
    Ok(Json(serde_json::from_str(filecontent).map_err(|e| {
        eprintln!("Failed to parse JSON data: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?))
}

async fn json(
    State(state): State<Arc<Mutex<AppState>>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, StatusCode> {
    info!("Handling /json with params: {:?}", params);

    let size = params
        .get("size")
        .and_then(|size| size.parse::<usize>().ok())
        .unwrap_or(1);

    if params.contains_key("shutdown") {
        _ = state.lock().unwrap().shutdown.take().unwrap().send(());
    }

    match size {
        1 => get_json_value(include_str!("data/1kb.json")),
        4 => get_json_value(include_str!("data/4kb.json")),
        8 => get_json_value(include_str!("data/8kb.json")),
        _ => Err(StatusCode::NOT_FOUND),
    }
}

async fn html(
    State(state): State<Arc<Mutex<AppState>>>,
    Query(params): Query<HashMap<String, String>>,
) -> Html<&'static str> {
    info!("Handling /html with params: {:?}", params);

    if params.contains_key("shutdown") {
        _ = state.lock().unwrap().shutdown.take().unwrap().send(());
    }

    Html(include_str!("data/4kb.html"))
}

struct AuthenticatedUser;

impl<B> FromRequest<B> for AuthenticatedUser
where
    B: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request(
        req: axum::extract::Request,
        _state: &B,
    ) -> Result<Self, Self::Rejection> {
        // Expected token (hardcoded for simplicity in the demo)
        let expected_token = "random_auth_token";

        let auth_header = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok());

        if let Some(auth_token) = auth_header {
            let token = auth_token.trim_start_matches("Bearer ");
            if token == expected_token {
                return Ok(AuthenticatedUser);
            }
        }

        Err((StatusCode::UNAUTHORIZED, "Invalid or missing token"))
    }
}

async fn protected_route(_: AuthenticatedUser) -> Result<Json<Value>, StatusCode> {
    info!("Handling /protected");

    get_json_value(include_str!("data/protected_data.json"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{self, Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use serde_json::Value;
    use tower::ServiceExt;

    fn get_app() -> Router {
        let (sender, _) = oneshot::channel();
        let state = AppState {
            shutdown: Some(sender),
        };
        app(state)
    }

    #[tokio::test]
    async fn hello_world() {
        let response = get_app()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"Hello, World!");
    }

    #[tokio::test]
    async fn json() {
        let response = get_app()
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/formats/json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            body.get("id").unwrap().as_number().unwrap().as_u64(),
            Some(1234567890)
        );
    }
}
