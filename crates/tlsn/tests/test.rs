use futures::{AsyncReadExt, AsyncWriteExt};
use rangeset::RangeSet;
use tlsn::{
    config::{
        prove::ProveConfig,
        prover::ProverConfig,
        tls::TlsClientConfig,
        tls_commit::{TlsCommitConfig, mpc::MpcTlsConfig},
        verifier::VerifierConfig,
    },
    connection::ServerName,
    hash::{HashAlgId, HashProvider},
    prover::Prover,
    transcript::{
        Direction, Transcript, TranscriptCommitConfig, TranscriptCommitment,
        TranscriptCommitmentKind, TranscriptSecret,
    },
    verifier::{Verifier, VerifierOutput},
    webpki::{CertificateDer, RootCertStore},
};
use tlsn_core::ProverOutput;
use tlsn_server_fixture::bind;
use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_DOMAIN};

use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::instrument;

// Maximum number of bytes that can be sent from prover to server
const MAX_SENT_DATA: usize = 1 << 12;
// Maximum number of application records sent from prover to server
const MAX_SENT_RECORDS: usize = 4;
// Maximum number of bytes that can be received by prover from server
const MAX_RECV_DATA: usize = 1 << 14;
// Maximum number of application records received by prover from server
const MAX_RECV_RECORDS: usize = 6;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn test() {
    tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("debug")),
        )
        .try_init()
        .unwrap();

    let (socket_0, socket_1) = tokio::io::duplex(2 << 23);

    let ((full_transcript, prover_output), verifier_output) =
        tokio::join!(prover(socket_0), verifier(socket_1));

    let partial_transcript = verifier_output.transcript.unwrap();
    let ServerName::Dns(server_name) = verifier_output.server_name.unwrap();

    assert_eq!(server_name.as_str(), SERVER_DOMAIN);
    assert!(!partial_transcript.is_complete());
    assert_eq!(
        partial_transcript
            .sent_authed()
            .iter_ranges()
            .next()
            .unwrap(),
        0..10
    );
    assert_eq!(
        partial_transcript
            .received_authed()
            .iter_ranges()
            .next()
            .unwrap(),
        0..10
    );

    let encoding_tree = prover_output
        .transcript_secrets
        .iter()
        .find_map(|secret| {
            if let TranscriptSecret::Encoding(tree) = secret {
                Some(tree)
            } else {
                None
            }
        })
        .unwrap();

    let encoding_commitment = prover_output
        .transcript_commitments
        .iter()
        .find_map(|commitment| {
            if let TranscriptCommitment::Encoding(commitment) = commitment {
                Some(commitment)
            } else {
                None
            }
        })
        .unwrap();

    let prove_sent = RangeSet::from(1..full_transcript.sent().len() - 1);
    let prove_recv = RangeSet::from(1..full_transcript.received().len() - 1);
    let idxs = [
        (Direction::Sent, prove_sent.clone()),
        (Direction::Received, prove_recv.clone()),
    ];
    let proof = encoding_tree.proof(idxs.iter()).unwrap();
    let (auth_sent, auth_recv) = proof
        .verify_with_provider(
            &HashProvider::default(),
            &verifier_output.encoder_secret.unwrap(),
            encoding_commitment,
            full_transcript.sent(),
            full_transcript.received(),
        )
        .unwrap();

    assert_eq!(auth_sent, prove_sent);
    assert_eq!(auth_recv, prove_recv);
}

#[instrument(skip(verifier_socket))]
async fn prover<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
    verifier_socket: T,
) -> (Transcript, ProverOutput) {
    let (client_socket, server_socket) = tokio::io::duplex(2 << 16);

    let server_task = tokio::spawn(bind(server_socket.compat()));

    let prover = Prover::new(ProverConfig::builder().build().unwrap())
        .commit(
            TlsCommitConfig::builder()
                .protocol(
                    MpcTlsConfig::builder()
                        .max_sent_data(MAX_SENT_DATA)
                        .max_sent_records(MAX_SENT_RECORDS)
                        .max_recv_data(MAX_RECV_DATA)
                        .max_recv_records_online(MAX_RECV_RECORDS)
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
            verifier_socket.compat(),
        )
        .await
        .unwrap();

    let (mut tls_connection, prover_fut) = prover
        .connect_with(
            TlsClientConfig::builder()
                .server_name(ServerName::Dns(SERVER_DOMAIN.try_into().unwrap()))
                .root_store(RootCertStore {
                    roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
                })
                .build()
                .unwrap(),
            client_socket.compat(),
        )
        .await
        .unwrap();
    let prover_task = tokio::spawn(prover_fut);

    tls_connection
        .write_all(b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();

    let mut response = vec![0u8; 1024];
    tls_connection.read_to_end(&mut response).await.unwrap();
    tls_connection.close().await.unwrap();

    let _ = server_task.await.unwrap();

    let mut prover = prover_task.await.unwrap().unwrap();
    let sent_tx_len = prover.transcript().sent().len();
    let recv_tx_len = prover.transcript().received().len();

    let mut builder = TranscriptCommitConfig::builder(prover.transcript());

    for kind in [
        TranscriptCommitmentKind::Encoding,
        TranscriptCommitmentKind::Hash {
            alg: HashAlgId::SHA256,
        },
    ] {
        builder
            .commit_with_kind(&(0..sent_tx_len), Direction::Sent, kind)
            .unwrap();
        builder
            .commit_with_kind(&(0..recv_tx_len), Direction::Received, kind)
            .unwrap();
        builder
            .commit_with_kind(&(1..sent_tx_len - 1), Direction::Sent, kind)
            .unwrap();
        builder
            .commit_with_kind(&(1..recv_tx_len - 1), Direction::Received, kind)
            .unwrap();
    }

    let transcript_commit = builder.build().unwrap();

    let mut builder = ProveConfig::builder(prover.transcript());

    builder.server_identity();

    builder.reveal_sent(&(0..10)).unwrap();
    builder.reveal_recv(&(0..10)).unwrap();

    builder.transcript_commit(transcript_commit);

    let config = builder.build().unwrap();
    let transcript = prover.transcript().clone();
    let output = prover.prove(&config).await.unwrap();
    prover.close().await.unwrap();

    (transcript, output)
}

#[instrument(skip(socket))]
async fn verifier<T: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    socket: T,
) -> VerifierOutput {
    let verifier = Verifier::new(
        VerifierConfig::builder()
            .root_store(RootCertStore {
                roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
            })
            .build()
            .unwrap(),
    );

    let verifier = verifier
        .commit(socket.compat())
        .await
        .unwrap()
        .accept()
        .await
        .unwrap()
        .run()
        .await
        .unwrap();

    let (output, verifier) = verifier.verify().await.unwrap().accept().await.unwrap();
    verifier.close().await.unwrap();

    output
}
