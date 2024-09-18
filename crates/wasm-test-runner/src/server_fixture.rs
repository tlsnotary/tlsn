use std::{env, net::IpAddr};

use tlsn_server_fixture;

use anyhow::Result;
use futures::Future;
use tokio::net::TcpListener;
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::{info, instrument};

use crate::{DEFAULT_SERVER_IP, DEFAULT_SERVER_PORT};

#[instrument]
pub async fn start() -> Result<impl Future<Output = Result<()>>> {
    let port: u16 = env::var("SERVER_PORT")
        .map(|port| port.parse().expect("port should be valid integer"))
        .unwrap_or(DEFAULT_SERVER_PORT);
    let addr: IpAddr = env::var("SERVER_IP")
        .map(|addr| addr.parse().expect("should be valid IP address"))
        .unwrap_or(IpAddr::V4(DEFAULT_SERVER_IP.parse().unwrap()));

    let listener = TcpListener::bind((addr, port)).await?;

    info!("listening on: {}", listener.local_addr()?);

    Ok(async move {
        loop {
            let (socket, addr) = listener.accept().await?;
            info!("accepted connection from: {}", addr);

            tokio::spawn(tlsn_server_fixture::bind(socket.compat()));
        }
    })
}
