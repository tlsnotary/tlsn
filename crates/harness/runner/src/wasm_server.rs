use std::{env, net::Ipv4Addr, path::PathBuf};

use anyhow::Result;
use axum::{
    Router,
    http::{HeaderName, HeaderValue},
};
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::{services::ServeDir, set_header::SetResponseHeaderLayer};

use crate::network::Namespace;

pub struct WasmServer {
    namespace: Namespace,
    path: PathBuf,
    addr: (Ipv4Addr, u16),
    handle: Option<duct::Handle>,
}

impl WasmServer {
    pub fn new(namespace: Namespace, path: PathBuf, addr: (Ipv4Addr, u16)) -> Self {
        Self {
            namespace,
            path,
            addr,
            handle: None,
        }
    }

    /// Spawns a new wasm server.
    pub fn start(&mut self) -> Result<()> {
        let handle = duct::cmd!(
            "sudo",
            "ip",
            "netns",
            "exec",
            &self.namespace.name(),
            "env",
            format!("ADDR={}", self.addr.0),
            format!("PORT={}", self.addr.1),
            &self.path,
        )
        .stderr_capture()
        .stdout_capture()
        .start()?;

        self.handle = Some(handle);

        Ok(())
    }

    /// Shuts down the wasm server.
    pub fn shutdown(&self) {
        self.handle.as_ref().inspect(|handle| {
            _ = handle.kill();
        });
    }
}

impl Drop for WasmServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

pub async fn main() -> Result<()> {
    let addr = env::var("ADDR")?;
    let port = env::var("PORT")?.parse::<u16>()?;

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
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("cache-control"),
            HeaderValue::from_static("no-store"),
        ))
        .service(files);

    // build our application with a single route
    let app = Router::new().fallback_service(service);

    let listener = TcpListener::bind((addr, port)).await?;

    axum::serve(listener, app).await?;

    Ok(())
}
