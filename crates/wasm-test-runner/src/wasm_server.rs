use std::{env, net::IpAddr};

use anyhow::Result;
use axum::{
    http::{HeaderName, HeaderValue},
    Router,
};
use futures::Future;
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::{services::ServeDir, set_header::SetResponseHeaderLayer};
use tracing::{info, instrument};

use crate::{DEFAULT_SERVER_IP, DEFAULT_WASM_PORT};

#[instrument]
pub async fn start() -> Result<impl Future<Output = Result<()>>> {
    let port: u16 = env::var("WASM_PORT")
        .map(|port| port.parse().expect("port should be valid integer"))
        .unwrap_or(DEFAULT_WASM_PORT);
    let addr: IpAddr = env::var("WASM_IP")
        .map(|addr| addr.parse().expect("should be valid IP address"))
        .unwrap_or(IpAddr::V4(DEFAULT_SERVER_IP.parse().unwrap()));

    let files = ServeDir::new("static");

    let service = ServiceBuilder::new()
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("cross-origin-embedder-policy"),
            HeaderValue::from_static("require-corp"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("cross-origin-opener-policy"),
            HeaderValue::from_static("same-origin"),
        ))
        .service(files);

    // build our application with a single route
    let app = Router::new().fallback_service(service);

    let listener = TcpListener::bind((addr, port)).await?;

    info!("listening on {}", listener.local_addr()?);

    Ok(async move {
        axum::serve(listener, app).await?;
        Ok(())
    })
}
