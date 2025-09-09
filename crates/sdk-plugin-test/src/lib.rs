use futures::{AsyncReadExt, AsyncWriteExt};

use tlsn_pdk::{
    config::{
        ProtocolConfig, ProtocolConfigValidator, ProverConfig, TlsConfig, VerifierConfig,
        VerifyConfig,
    },
    connection::ServerName,
    entry,
    prover::{ProveConfig, Prover},
    verifier::Verifier,
    webpki::{CertificateDer, RootCertStore},
};
use tlsn_server_fixture_certs::CA_CERT_DER;

async fn main(arg: Vec<u8>) -> Result<Vec<u8>, String> {
    if arg[0] == 0 {
        prover().await
    } else {
        verifier().await
    }
}

entry!(main);

async fn prover() -> Result<Vec<u8>, String> {
    let name = ServerName::Dns("test-server.io".try_into().unwrap());

    let mut builder = TlsConfig::builder();
    builder.root_store(RootCertStore {
        roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
    });
    let tls_config = builder.build().unwrap();

    let config = ProverConfig::builder()
        .server_name(name)
        .tls_config(tls_config)
        .protocol_config(
            ProtocolConfig::builder()
                .max_sent_data(1024)
                .max_recv_data(1024)
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    let mut prover = Prover::new(config).setup().await.unwrap();

    let (mut conn, prover_fut) = prover.connect().await.unwrap();

    let (response, prover) = futures::join!(
        async {
            conn.write_all(b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            conn.close().await.unwrap();

            let mut response = vec![0u8; 1024];
            conn.read_to_end(&mut response).await.unwrap();

            response
        },
        prover_fut,
    );

    let mut prover = prover.unwrap();

    let mut builder = ProveConfig::builder(prover.transcript());

    let output = prover.prove(&builder.build().unwrap()).await.unwrap();

    prover.close().await.unwrap();

    Ok(response)
}

async fn verifier() -> Result<Vec<u8>, String> {
    let config = VerifierConfig::builder()
        .root_store(RootCertStore {
            roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
        })
        .protocol_config_validator(
            ProtocolConfigValidator::builder()
                .max_sent_data(1024)
                .max_recv_data(4096)
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    let mut verifier = Verifier::new(config)
        .setup()
        .await
        .unwrap()
        .run()
        .await
        .unwrap();

    let output = verifier.verify(&VerifyConfig::default()).await.unwrap();

    verifier.close().await.unwrap();

    Ok(vec![])
}
