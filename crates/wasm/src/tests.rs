#![allow(clippy::single_range_in_vec_init)]

use std::collections::HashMap;

use tls_core::verify::WebPkiVerifier;
use tlsn_common::config::{ProtocolConfig, ProtocolConfigValidator};
use tlsn_prover::tls::{Prover, ProverConfig};
use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_DOMAIN};
use tlsn_verifier::tls::{Verifier, VerifierConfig};
use wasm_bindgen::prelude::*;

use crate::{
    prover::JsProver,
    types::{Commit, HttpRequest, Method, Reveal},
    verifier::JsVerifier,
};

#[wasm_bindgen]
pub async fn test_prove() -> Result<(), JsValue> {
    let mut root_store = tls_core::anchors::RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();

    let protocol_config = ProtocolConfig::builder()
        .max_sent_data(1024)
        .max_recv_data(1024)
        .build()
        .unwrap();

    let prover = Prover::new(
        ProverConfig::builder()
            .id("test")
            .server_dns(SERVER_DOMAIN)
            .root_cert_store(root_store)
            .protocol_config(protocol_config)
            .build()
            .unwrap(),
    );

    let mut prover = JsProver::from(prover);

    let uri = format!("https://{}/bytes?size=512", SERVER_DOMAIN);

    prover
        .setup("ws://localhost:8080/tcp?addr=localhost%3A8010")
        .await?;

    prover
        .send_request(
            "ws://localhost:8080/tcp?addr=localhost%3A8083",
            HttpRequest {
                method: Method::GET,
                uri,
                headers: HashMap::from([("Accept".to_string(), b"*".to_vec())]),
                body: None,
            },
        )
        .await?;

    prover
        .reveal(Reveal {
            sent: vec![0..10],
            recv: vec![0..10],
        })
        .await?;

    Ok(())
}

#[wasm_bindgen]
pub async fn test_notarize() -> Result<(), JsValue> {
    let mut root_store = tls_core::anchors::RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();

    let protocol_config = ProtocolConfig::builder()
        .max_sent_data(1024)
        .max_recv_data(1024)
        .build()
        .unwrap();

    let prover = Prover::new(
        ProverConfig::builder()
            .id("test")
            .server_dns(SERVER_DOMAIN)
            .root_cert_store(root_store)
            .protocol_config(protocol_config)
            .build()
            .unwrap(),
    );

    let mut prover = JsProver::from(prover);

    let uri = format!("https://{SERVER_DOMAIN}/bytes?size=512");

    prover
        .setup("ws://localhost:8080/tcp?addr=localhost%3A8011")
        .await?;

    prover
        .send_request(
            "ws://localhost:8080/tcp?addr=localhost%3A8083",
            HttpRequest {
                method: Method::GET,
                uri,
                headers: HashMap::from([("Accept".to_string(), b"*".to_vec())]),
                body: None,
            },
        )
        .await?;

    let _ = prover.transcript()?;

    prover
        .notarize(Commit {
            sent: vec![0..10],
            recv: vec![0..10],
        })
        .await?;

    Ok(())
}

#[wasm_bindgen]
pub async fn test_verifier() -> Result<(), JsValue> {
    let mut root_store = tls_core::anchors::RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();

    let config_validator = ProtocolConfigValidator::builder()
        .max_sent_data(1024)
        .max_recv_data(1024)
        .build()
        .unwrap();

    let config = VerifierConfig::builder()
        .id("test")
        .protocol_config_validator(config_validator)
        .cert_verifier(WebPkiVerifier::new(root_store, None))
        .build()
        .unwrap();

    let mut verifier = JsVerifier::from(Verifier::new(config));
    verifier
        .connect("ws://localhost:8080/tcp?addr=localhost%3A8012")
        .await?;
    verifier.verify().await?;

    Ok(())
}
