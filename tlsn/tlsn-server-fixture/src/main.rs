use std::env;

use tlsn_server_fixture::bind;
use tokio::net::TcpListener;
use tokio_util::compat::TokioAsyncWriteCompatExt;

#[tokio::main]
async fn main() {
    let port = env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let listener = TcpListener::bind(&format!("0.0.0.0:{port}")).await.unwrap();

    loop {
        let (socket, _) = listener.accept().await.unwrap();
        tokio::spawn(bind(socket.compat_write()));
    }
}
