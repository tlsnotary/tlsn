use std::future::IntoFuture;

use tlsn::{
    Session,
    config::{
        prove::ProveConfig,
        prover::ProverConfig,
        tls::TlsClientConfig,
        tls_commit::{TlsCommitConfig, mpc::MpcTlsConfig, proxy::ProxyTlsConfig},
        verifier::VerifierConfig,
    },
    connection::{DnsName, ServerName},
    hash::HashAlgId,
    transcript::{TranscriptCommitConfig, TranscriptCommitment, TranscriptCommitmentKind},
    verifier::VerifierOutput,
    webpki::{CertificateDer, RootCertStore},
};
use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_DOMAIN};

use http_body_util::{BodyExt as _, Empty};
use hyper::{Request, StatusCode, body::Bytes};

use crate::{IoProvider, io::FuturesIo, spawn};

// Maximum number of bytes that can be sent from prover to server
const MAX_SENT_DATA: usize = 1 << 11;
// Maximum number of bytes that can be received by prover from server
const MAX_RECV_DATA: usize = 1 << 11;

crate::test!("mpc", prover_mpc, verifier);
crate::test!("proxy", prover_proxy, verifier);

async fn prover_mpc(provider: &IoProvider) {
    let config = TlsCommitConfig::builder()
        .protocol(
            MpcTlsConfig::builder()
                .max_sent_data(MAX_SENT_DATA)
                .max_recv_data(MAX_RECV_DATA)
                .defer_decryption_from_start(true)
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    prover(provider, config).await
}

async fn prover_proxy(provider: &IoProvider) {
    let config = TlsCommitConfig::builder()
        .protocol(
            ProxyTlsConfig::builder()
                .server_name(DnsName::try_from(SERVER_DOMAIN).unwrap())
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    prover(provider, config).await
}

async fn prover(provider: &IoProvider, config: TlsCommitConfig) {
    let io = provider.provide_proto_io().await.unwrap();
    let mut session = Session::new(io);
    let prover = session
        .new_prover(ProverConfig::builder().build().unwrap())
        .unwrap();

    let (session, handle) = session.split();

    _ = spawn(session);

    let is_proxy = matches!(
        config.protocol(),
        tlsn::config::tls_commit::TlsCommitProtocolConfig::Proxy(_)
    );
    let prover = prover.commit(config).await.unwrap();

    let mut prover = if is_proxy {
        let (tls_connection, prover) = prover
            .connect_proxy(
                TlsClientConfig::builder()
                    .server_name(ServerName::Dns(SERVER_DOMAIN.try_into().unwrap()))
                    .root_store(RootCertStore {
                        roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
                    })
                    .build()
                    .unwrap(),
            )
            .unwrap();

        let prover_task = spawn(prover.into_future());

        let (mut request_sender, connection) =
            hyper::client::conn::http1::handshake(FuturesIo::new(tls_connection))
                .await
                .unwrap();

        _ = spawn(connection);

        let request = Request::builder()
            .uri(format!(
                "https://{}/bytes?size={recv}",
                SERVER_DOMAIN,
                recv = MAX_RECV_DATA - 256
            ))
            .header("Host", SERVER_DOMAIN)
            .header("Connection", "close")
            .method("GET")
            .body(Empty::<Bytes>::new())
            .unwrap();

        let response = request_sender.send_request(request).await.unwrap();

        assert!(response.status() == StatusCode::OK);

        let _ = response.into_body().collect().await.unwrap().to_bytes();

        prover_task.await.unwrap().unwrap()
    } else {
        let (tls_connection, prover) = prover
            .connect_mpc(
                TlsClientConfig::builder()
                    .server_name(ServerName::Dns(SERVER_DOMAIN.try_into().unwrap()))
                    .root_store(RootCertStore {
                        roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
                    })
                    .build()
                    .unwrap(),
                provider.provide_server_io().await.unwrap(),
            )
            .unwrap();

        let prover_task = spawn(prover.into_future());

        let (mut request_sender, connection) =
            hyper::client::conn::http1::handshake(FuturesIo::new(tls_connection))
                .await
                .unwrap();

        _ = spawn(connection);

        let request = Request::builder()
            .uri(format!(
                "https://{}/bytes?size={recv}",
                SERVER_DOMAIN,
                recv = MAX_RECV_DATA - 256
            ))
            .header("Host", SERVER_DOMAIN)
            .header("Connection", "close")
            .method("GET")
            .body(Empty::<Bytes>::new())
            .unwrap();

        let response = request_sender.send_request(request).await.unwrap();

        assert!(response.status() == StatusCode::OK);

        let _ = response.into_body().collect().await.unwrap().to_bytes();

        prover_task.await.unwrap().unwrap()
    };

    let (sent_len, recv_len) = prover.transcript().len();

    let mut builder = TranscriptCommitConfig::builder(prover.transcript());

    builder.default_kind(TranscriptCommitmentKind::Hash {
        alg: HashAlgId::SHA256,
    });

    builder.commit_sent(&(0..sent_len)).unwrap();
    builder.commit_recv(&(0..recv_len)).unwrap();

    let transcript_commit = builder.build().unwrap();

    let mut builder = ProveConfig::builder(prover.transcript());

    builder
        .server_identity()
        .reveal_sent(&(0..sent_len - 1))
        .unwrap()
        .reveal_recv(&(2..recv_len))
        .unwrap()
        .transcript_commit(transcript_commit);

    let config = builder.build().unwrap();

    prover.prove(&config).await.unwrap();
    prover.close().await.unwrap();
    handle.close();
}

async fn verifier(provider: &IoProvider) {
    let io = provider.provide_proto_io().await.unwrap();
    let mut session = Session::new(io);

    let config = VerifierConfig::builder()
        .root_store(RootCertStore {
            roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
        })
        .build()
        .unwrap();
    let verifier = session.new_verifier(config).unwrap();

    let (session, handle) = session.split();

    _ = spawn(session);

    let verifier = verifier.commit().await.unwrap();

    let is_proxy = matches!(
        verifier.request().protocol(),
        tlsn::config::tls_commit::TlsCommitProtocolConfig::Proxy(_)
    );

    let verifier = verifier.accept().await.unwrap();

    let verifier = if is_proxy {
        let server_io = provider.provide_server_io().await.unwrap();
        verifier.run_proxy(server_io).await.unwrap()
    } else {
        verifier.run_mpc().await.unwrap()
    };

    let (
        VerifierOutput {
            server_name,
            transcript_commitments,
            ..
        },
        verifier,
    ) = verifier.verify().await.unwrap().accept().await.unwrap();

    verifier.close().await.unwrap();
    handle.close();

    let ServerName::Dns(server_name) = server_name.unwrap();

    assert_eq!(server_name.as_str(), SERVER_DOMAIN);
    assert!(
        transcript_commitments
            .iter()
            .any(|commitment| matches!(commitment, TranscriptCommitment::Hash { .. }))
    );
}
