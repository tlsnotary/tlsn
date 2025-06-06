use std::{env, io};

use tlsn_server_fixture::{bind, DEFAULT_FIXTURE_PORT};
use tokio::net::TcpListener;
use tokio_util::compat::TokioAsyncWriteCompatExt;
use tracing::info;

#[tokio::main]
async fn main() -> io::Result<()> {
    tracing_subscriber::fmt::init();
    let addr = env::var("ADDR").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = env::var("PORT")
        .map(|port| port.parse().unwrap())
        .unwrap_or_else(|_| DEFAULT_FIXTURE_PORT);
    let listener = TcpListener::bind((addr, port)).await?;

    info!("Starting server fixture on port {port}");
    loop {
        let (socket, _) = listener.accept().await?;
        tokio::spawn(bind(socket.compat_write()));
    }
}
