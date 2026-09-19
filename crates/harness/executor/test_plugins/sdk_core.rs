use futures::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(not(target_arch = "wasm32"))]
use tlsn_sdk_core::{HttpRequest, NetworkSetting, ProverConfig, Reveal, SdkProver};
use tlsn_sdk_core::{SdkVerifier, VerifierConfig};
use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_DOMAIN};

use crate::IoProvider;

// Maximum number of bytes that can be sent from prover to server
const MAX_SENT_DATA: usize = 1 << 11;
// Maximum number of bytes that can be received by prover from server
const MAX_RECV_DATA: usize = 1 << 11;

crate::test!("sdk_core", prover, verifier);

async fn prover(provider: &IoProvider) {
    #[cfg(target_arch = "wasm32")]
    return prover_wasm(provider).await;

    #[cfg(not(target_arch = "wasm32"))]
    prover_core(provider).await;
}

#[cfg(not(target_arch = "wasm32"))]
async fn prover_core(provider: &IoProvider) {
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

    let mut io = prover.finish().await.unwrap();
    io.write_all(b"prover-finished").await.unwrap();
    let mut response = [0; 17];
    io.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"verifier-finished");
}

#[cfg(target_arch = "wasm32")]
async fn prover_wasm(provider: &IoProvider) {
    use js_sys::{Promise, Uint8Array};
    use std::collections::HashMap;
    use tlsn_wasm::{
        prover::{JsProver, ProverConfig},
        types::{HttpRequest, Method, Reveal},
    };
    use wasm_bindgen::{JsCast, prelude::*};
    use wasm_bindgen_futures::JsFuture;

    #[wasm_bindgen]
    extern "C" {
        type TestIoChannel;

        #[wasm_bindgen(method)]
        fn read(this: &TestIoChannel) -> Promise;

        #[wasm_bindgen(method)]
        fn write(this: &TestIoChannel, data: &Uint8Array) -> Promise;
    }

    let config: ProverConfig = serde_json::from_value(serde_json::json!({
        "server_name": SERVER_DOMAIN,
        "mode": "Mpc",
        "max_sent_data": MAX_SENT_DATA,
        "max_sent_records": null,
        "max_recv_data_online": null,
        "max_recv_data": MAX_RECV_DATA,
        "max_recv_records_online": null,
        "defer_decryption_from_start": true,
        "network": "Latency",
        "client_auth": null,
        "root_certs": [CA_CERT_DER],
    }))
    .unwrap();
    let mut prover = JsProver::new(config).unwrap();

    let proto_io = provider.provide_proto_js_io().await.unwrap();
    let retained_io = proto_io.unchecked_ref::<TestIoChannel>();
    prover
        .setup(proto_io.clone().unchecked_into())
        .await
        .unwrap();

    let server_io = provider.provide_server_js_io().await.unwrap();
    let response = prover
        .send_request(
            Some(server_io.unchecked_into()),
            HttpRequest {
                uri: format!(
                    "https://{}/bytes?size={}",
                    SERVER_DOMAIN,
                    MAX_RECV_DATA - 256
                ),
                method: Method::GET,
                headers: HashMap::from([
                    ("Host".to_string(), SERVER_DOMAIN.as_bytes().to_vec()),
                    ("Connection".to_string(), b"close".to_vec()),
                ]),
                body: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(response.status, 200);

    let transcript = prover.transcript().unwrap();
    prover
        .reveal(
            Reveal {
                sent: vec![0..transcript.sent.len() - 1],
                recv: vec![2..transcript.recv.len()],
                server_identity: true,
            },
            None,
        )
        .await
        .unwrap();
    prover.finish().await.unwrap();

    JsFuture::from(retained_io.write(&Uint8Array::from(b"prover-finished".as_slice())))
        .await
        .unwrap();
    let response = JsFuture::from(retained_io.read()).await.unwrap();
    assert_eq!(Uint8Array::new(&response).to_vec(), b"verifier-finished");
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

    let mut io = verifier.finish().await.unwrap();
    let mut request = [0; 15];
    io.read_exact(&mut request).await.unwrap();
    assert_eq!(&request, b"prover-finished");
    io.write_all(b"verifier-finished").await.unwrap();
}
