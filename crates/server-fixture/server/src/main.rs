use std::{env, io};

use tlsn_server_fixture::{bind, DEFAULT_FIXTURE_PORT};
use tokio::net::TcpListener;
use tokio_util::compat::TokioAsyncWriteCompatExt;

#[tokio::main]
async fn main() -> io::Result<()> {
    let port = env::var("PORT").unwrap_or_else(|_| DEFAULT_FIXTURE_PORT.to_string());
    let listener = TcpListener::bind(&format!("0.0.0.0:{port}")).await?;

    loop {
        let (socket, _) = listener.accept().await?;
        tokio::spawn(bind(socket.compat_write()));
    }
}
