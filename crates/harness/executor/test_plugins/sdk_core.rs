use tlsn_sdk_core::{
    HttpRequest, NetworkSetting, ProverConfig, Reveal, SdkProver, SdkVerifier, VerifierConfig,
};
use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_DOMAIN};

use crate::IoProvider;

// Maximum number of bytes that can be sent from prover to server
const MAX_SENT_DATA: usize = 1 << 11;
// Maximum number of bytes that can be received by prover from server
const MAX_RECV_DATA: usize = 1 << 11;

crate::test!("sdk_core", prover, verifier);

async fn prover(provider: &IoProvider) {
    let config = ProverConfig::builder(SERVER_DOMAIN)
        .max_sent_data(MAX_SENT_DATA)
        .max_recv_data(MAX_RECV_DATA)
        .defer_decryption_from_start(true)
        .network(NetworkSetting::Latency)
        .root_certs(vec![CA_CERT_DER.to_vec()])
        .build()
        .unwrap();

    let mut prover = SdkProver::new(config).unwrap();

    let proto_io = provider.provide_proto_io().await.unwrap();
    prover.setup(proto_io).await.unwrap();

    let server_io = provider.provide_server_io().await.unwrap();
    let request = HttpRequest::get(format!(
        "https://{}/bytes?size={}",
        SERVER_DOMAIN,
        MAX_RECV_DATA - 256
    ))
    .header("Host", SERVER_DOMAIN)
    .header("Connection", "close");

    let response = match prover.mode() {
        tlsn_sdk_core::ProverMode::Mpc => {
            prover.send_request_mpc(server_io, request).await.unwrap()
        }
        tlsn_sdk_core::ProverMode::Proxy => prover.send_request_proxy(request).await.unwrap(),
    };
    assert_eq!(response.status, 200);

    let transcript = prover.transcript().unwrap();
    let sent_len = transcript.sent.len();
    let recv_len = transcript.recv.len();

    prover
        .reveal(
            Reveal::new()
                .sent(0..sent_len - 1)
                .recv(2..recv_len)
                .server_identity(true),
            None,
        )
        .await
        .unwrap();

    assert!(prover.is_complete());
}

async fn verifier(provider: &IoProvider) {
    let config = VerifierConfig::builder()
        .max_sent_data(MAX_SENT_DATA)
        .max_recv_data(MAX_RECV_DATA)
        .root_certs(vec![CA_CERT_DER.to_vec()])
        .build()
        .unwrap();

    let mut verifier = SdkVerifier::new(config);

    let proto_io = provider.provide_proto_io().await.unwrap();
    verifier.connect(proto_io).await.unwrap();

    if verifier.setup().await.unwrap().is_some() {
        let server_io = provider.provide_server_io().await.unwrap();
        verifier.set_server_socket(server_io).unwrap();
    }
    verifier.run().await.unwrap();

    let output = verifier.verify().await.unwrap();

    assert_eq!(output.server_name.as_deref(), Some(SERVER_DOMAIN));
    assert!(output.transcript.is_some());
    assert!(verifier.is_complete());
}
