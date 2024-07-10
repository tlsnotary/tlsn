use dotenv::dotenv;
use http_body_util::{BodyExt, Empty};
use hyper::{body::Bytes, Request, StatusCode};
use hyper_util::rt::TokioIo;
use notary_client::{Accepted, NotarizationRequest, NotaryClient};
use std::{
    env,
    io::{self, Write},
};
use tlsn_core::{commitment::CommitmentKind, proof::TlsProof};
use tlsn_examples::PayoutResponse;
use tlsn_prover::tls::{Prover, ProverConfig};
use tokio::io::AsyncWriteExt as _;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::{debug, info};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // todo: replace this logic with logic that listens to the smart contract events and fulfills a payout to the number specified. It then uses that uuid to spin up the notary and prove that the payment went through.
    print!("Enter payout id: ");
    io::stdout().flush().expect("Failed to flush stdout");

    let mut payout_id = String::new();
    io::stdin()
        .read_line(&mut payout_id)
        .expect("Failed to read line");

    let payout_id = payout_id.trim();

    println!("Payout ID: {}", payout_id);
    let server_domain = "api.sandbox.pawapay.cloud";

    tracing_subscriber::fmt()
        .with_env_filter("debug,yamux=info")
        .init();

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
        .server_dns(server_domain)
        .build()
        .unwrap();

    let prover = Prover::new(config)
        .setup(notary_connection.compat())
        .await
        .unwrap();

    let client_socket = tokio::net::TcpStream::connect((server_domain, 443))
        .await
        .unwrap();

    let (tls_connection, prover_fut) = prover.connect(client_socket.compat()).await.unwrap();

    let tls_connection = TokioIo::new(tls_connection.compat());

    let prover_ctrl = prover_fut.control();

    let prover_task = tokio::spawn(prover_fut);

    let (mut request_sender, connection) = hyper::client::conn::http1::handshake(tls_connection)
        .await
        .unwrap();

    tokio::spawn(connection);

    let url = format!("https://{}/payouts/{}", server_domain, payout_id);

    let request = Request::get(url.clone())
        .header("Authorization", format!("Bearer {}", jwt.as_str()))
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .header(hyper::header::HOST, "api.sandbox.pawapay.cloud")
        .header("Connection", "close")
        .header("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate")
        .header("Pragma", "no-cache")
        .header("Expires", "0")
        .header("Accept", "*/*")
        .body(Empty::<Bytes>::new()).unwrap();

    debug!("Sending request: {:?}", request);

    prover_ctrl.defer_decryption().await.unwrap();

    let response = request_sender.send_request(request).await.unwrap();

    debug!("Sent request");

    assert!(response.status() == StatusCode::OK, "{}", response.status());

    debug!("Request OK");

    let payload = response.into_body().collect().await.unwrap().to_bytes();
    debug!("Payload: {:?}", payload);
    let response_body = String::from_utf8_lossy(&payload);
    println!("Response: {}", response_body);

    let payout_responses: Vec<PayoutResponse> = serde_json::from_str(&response_body).unwrap();

    for payout_response in payout_responses {
        assert_eq!(
            payout_response.status, "COMPLETED",
            "Payout status is not COMPLETED"
        );
    }

    let prover = prover_task.await.unwrap().unwrap();

    let mut prover = prover.to_http().unwrap().start_notarize();

    prover.commit().unwrap();

    let notarized_session = prover.finalize().await.unwrap();

    debug!("Notarization complete!");

    let mut file = tokio::fs::File::create("payout_status.json").await.unwrap();
    file.write_all(
        serde_json::to_string_pretty(notarized_session.session())
            .unwrap()
            .as_bytes(),
    )
    .await
    .unwrap();

    let session_proof = notarized_session.session_proof();

    let mut proof_builder = notarized_session.session().data().build_substrings_proof();

    let request = &notarized_session.transcript().requests[0];

    proof_builder
        .reveal_sent(&request.without_data(), CommitmentKind::Blake3)
        .unwrap();

    proof_builder
        .reveal_sent(&request.request.target, CommitmentKind::Blake3)
        .unwrap();

    for header in &request.headers {
        // todo: reveal the payment uuid and the status as well
        if header.name.as_str().eq_ignore_ascii_case("Host") {
            proof_builder
                .reveal_sent(header, CommitmentKind::Blake3)
                .unwrap();
        } else {
            proof_builder
                .reveal_sent(&header.without_value(), CommitmentKind::Blake3)
                .unwrap();
        }
    }

    let response = &notarized_session.transcript().responses[0];

    proof_builder
        .reveal_recv(response, CommitmentKind::Blake3)
        .unwrap();

    let substrings_proof = proof_builder.build().unwrap();

    let proof = TlsProof {
        session: session_proof,
        substrings: substrings_proof,
    };

    //todo: extract the signature and send it on chain
    // for now: just verify the signature here and sign a message with a wallet in this .env

    let mut file = tokio::fs::File::create("payout_status_proof.json")
        .await
        .unwrap();
    file.write_all(serde_json::to_string_pretty(&proof).unwrap().as_bytes())
        .await
        .unwrap();

    Ok(())
}
