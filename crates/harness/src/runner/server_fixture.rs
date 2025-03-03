use std::{env, net::IpAddr};

use futures_limit::AsyncReadDelayExt;
use tlsn_server_fixture;

use anyhow::Result;
use tokio::net::TcpListener;
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::{info, instrument};

use crate::{config::SERVER_LATENCY, DEFAULT_SERVER_IP, DEFAULT_SERVER_PORT};

#[instrument]
pub async fn start() -> Result<()> {
    let port: u16 = env::var("SERVER_PORT")
        .map(|port| port.parse().expect("port should be valid integer"))
        .unwrap_or(DEFAULT_SERVER_PORT);
    let addr: IpAddr = env::var("SERVER_IP")
        .map(|addr| addr.parse().expect("should be valid IP address"))
        .unwrap_or(IpAddr::V4(DEFAULT_SERVER_IP.parse().unwrap()));

    let listener = TcpListener::bind((addr, port)).await?;

    info!("listening on: {}", listener.local_addr()?);

    loop {
        let (socket, addr) = listener.accept().await?;
        info!("accepted connection from: {}", addr);

        let (io, delay) = socket.compat().delay(SERVER_LATENCY / 2);
        tokio::spawn(delay);
        tokio::spawn(tlsn_server_fixture::bind(io));
    }
}
