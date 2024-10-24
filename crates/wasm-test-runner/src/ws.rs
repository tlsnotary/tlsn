use std::{env, net::IpAddr};

use anyhow::{Context, Result};
use futures::Future;
use tokio::net::TcpListener;
use tracing::{info, instrument};

use crate::{DEFAULT_SERVER_IP, DEFAULT_WS_PORT};

#[instrument]
pub async fn start() -> Result<impl Future<Output = Result<()>>> {
    let port: u16 = env::var("PROXY_PORT")
        .map(|port| port.parse().expect("port should be valid integer"))
        .unwrap_or(DEFAULT_WS_PORT);
    let addr: IpAddr = env::var("PROXY_IP")
        .map(|addr| addr.parse().expect("should be valid IP address"))
        .unwrap_or(IpAddr::V4(DEFAULT_SERVER_IP.parse().unwrap()));

    let listener = TcpListener::bind((addr, port))
        .await
        .context("failed to bind to address")?;

    info!("listening on: {}", listener.local_addr()?);

    Ok(websocket_relay::run(listener))
}
