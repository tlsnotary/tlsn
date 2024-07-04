use dotenv::dotenv;
use notary_client::{Accepted, NotarizationRequest, NotaryClient};
use std::{
    env,
    io::{self, Write},
    sync::Arc,
};
use tokio::{io::AsyncWriteExt as _, sync::Mutex};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tlsn_prover::tls::{Prover, ProverConfig};
use tracing::{debug, error, info, warn};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    print!("Enter payout id: ");
    io::stdout().flush().expect("Failed to flush stdout");

    let mut payout_id = String::new();
    io::stdin()
        .read_line(&mut payout_id)
        .expect("Failed to read line");

    let payout_id = payout_id.trim();

    println!("Payout ID: {}", payout_id);
    dotenv().ok();

    let jwt = env::var("JWT").expect("JWT must be set");

    const NOTARY_HOST: &str = "notary.pse.dev";
    const NOTARY_PORT: u16 = 443;

    let notary_client = NotaryClient::builder()
        .host(NOTARY_HOST)
        .port(NOTARY_PORT)
        .enable_tls(true)
        .build()
        .unwrap();
    info!("Created Notary Client");

    let notarization_request = NotarizationRequest::builder().build().unwrap();

    let Accepted {
        io: notary_connection,
        id: session_id,
        ..
    } = notary_client
        .request_notarization(notarization_request)
        .await
        .unwrap();

    let config = ProverConfig::builder()
        .id(session_id)
        .server_dns("api.sandbox.pawapay.cloud")
        .build()
        .unwrap();

    let prover = Prover::new(config)
        .setup(notary_connection.compat())
        .await
        .unwrap();

    let client_socket = tokio::net::TcpStream::connect(("api.sandbox.pawapay.cloud", 443))
        .await
        .unwrap();

    let (tls_connection, prover_fut) = prover.connect(client_socket.compat()).await.unwrap();

    let tls_connection = TokioIo::new(tls_connection.compat());

    
}
