use futures::{AsyncReadExt, AsyncWriteExt};
use mpz_predicate::{Pred, eq};
use rangeset::set::RangeSet;
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
    tracing_subscriber::fmt::init();

    let (socket_0, socket_1) = tokio::io::duplex(2 << 23);

    let ((full_transcript, prover_output), verifier_output) =
        tokio::join!(prover(socket_0), verifier(socket_1));

    let partial_transcript = verifier_output.transcript.unwrap();
    let ServerName::Dns(server_name) = verifier_output.server_name.unwrap();

    assert_eq!(server_name.as_str(), SERVER_DOMAIN);
    assert!(!partial_transcript.is_complete());
    assert_eq!(
        partial_transcript.sent_authed().iter().next().unwrap(),
        0..10
    );
    assert_eq!(
        partial_transcript.received_authed().iter().next().unwrap(),
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
        .connect(
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
    tls_connection.close().await.unwrap();

    let mut response = vec![0u8; 1024];
    tls_connection.read_to_end(&mut response).await.unwrap();

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

// Predicate name for testing
const TEST_PREDICATE: &str = "test_first_byte";

/// Test that a correct predicate passes verification.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn test_predicate_passes() {
    let (socket_0, socket_1) = tokio::io::duplex(2 << 23);

    // Request is "GET / HTTP/1.1\r\n..." - index 10 is '/' (in "HTTP/1.1")
    // Using index 10 to avoid overlap with revealed range (0..10)
    // Verifier uses the same predicate - should pass
    let prover_predicate = eq(10, b'/');

    let (prover_result, verifier_result) = tokio::join!(
        prover_with_predicate(socket_0, prover_predicate),
        verifier_with_predicate(socket_1, || eq(10, b'/'))
    );

    prover_result.expect("prover should succeed");
    verifier_result.expect("verifier should succeed with correct predicate");
}

/// Test that a wrong predicate is rejected by the verifier.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn test_wrong_predicate_rejected() {
    let (socket_0, socket_1) = tokio::io::duplex(2 << 23);

    // Request is "GET / HTTP/1.1\r\n..." - index 10 is '/'
    // Verifier uses a DIFFERENT predicate that checks for 'X' - should fail
    let prover_predicate = eq(10, b'/');

    let (prover_result, verifier_result) = tokio::join!(
        prover_with_predicate(socket_0, prover_predicate),
        verifier_with_predicate(socket_1, || eq(10, b'X'))
    );

    // Prover may succeed or fail depending on when verifier rejects
    let _ = prover_result;

    // Verifier should fail because predicate evaluates to false
    assert!(
        verifier_result.is_err(),
        "verifier should reject wrong predicate"
    );
}

/// Test that prover can't prove a predicate their data doesn't satisfy.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn test_unsatisfied_predicate_rejected() {
    let (socket_0, socket_1) = tokio::io::duplex(2 << 23);

    // Request is "GET / HTTP/1.1\r\n..." - index 10 is '/'
    // Both parties use eq(10, b'X') but prover's data has '/' at index 10
    // This tests that a prover can't cheat - the predicate must actually be satisfied
    let prover_predicate = eq(10, b'X');

    let (prover_result, verifier_result) = tokio::join!(
        prover_with_predicate(socket_0, prover_predicate),
        verifier_with_predicate(socket_1, || eq(10, b'X'))
    );

    // Prover may succeed or fail depending on when verifier rejects
    let _ = prover_result;

    // Verifier should fail because prover's data doesn't satisfy the predicate
    assert!(
        verifier_result.is_err(),
        "verifier should reject unsatisfied predicate"
    );
}

#[instrument(skip(verifier_socket, predicate))]
async fn prover_with_predicate<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
    verifier_socket: T,
    predicate: Pred,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (client_socket, server_socket) = tokio::io::duplex(2 << 16);

    let server_task = tokio::spawn(bind(server_socket.compat()));

    let prover = Prover::new(ProverConfig::builder().build()?)
        .commit(
            TlsCommitConfig::builder()
                .protocol(
                    MpcTlsConfig::builder()
                        .max_sent_data(MAX_SENT_DATA)
                        .max_sent_records(MAX_SENT_RECORDS)
                        .max_recv_data(MAX_RECV_DATA)
                        .max_recv_records_online(MAX_RECV_RECORDS)
                        .build()?,
                )
                .build()?,
            verifier_socket.compat(),
        )
        .await?;

    let (mut tls_connection, prover_fut) = prover
        .connect(
            TlsClientConfig::builder()
                .server_name(ServerName::Dns(SERVER_DOMAIN.try_into()?))
                .root_store(RootCertStore {
                    roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
                })
                .build()?,
            client_socket.compat(),
        )
        .await?;
    let prover_task = tokio::spawn(prover_fut);

    tls_connection
        .write_all(b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n")
        .await?;
    tls_connection.close().await?;

    let mut response = vec![0u8; 1024];
    tls_connection.read_to_end(&mut response).await?;

    let _ = server_task.await?;

    let mut prover = prover_task.await??;

    let mut builder = ProveConfig::builder(prover.transcript());
    builder.server_identity();
    builder.reveal_sent(&(0..10))?;
    builder.reveal_recv(&(0..10))?;
    builder.predicate(TEST_PREDICATE, Direction::Sent, predicate)?;

    let config = builder.build()?;
    prover.prove(&config).await?;
    prover.close().await?;

    Ok(())
}

async fn verifier_with_predicate<T, F>(
    socket: T,
    make_predicate: F,
) -> Result<VerifierOutput, Box<dyn std::error::Error + Send + Sync>>
where
    T: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static,
    F: Fn() -> Pred + Send + Sync + 'static,
{
    let verifier = Verifier::new(
        VerifierConfig::builder()
            .root_store(RootCertStore {
                roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
            })
            .build()?,
    );

    let verifier = verifier
        .commit(socket.compat())
        .await?
        .accept()
        .await?
        .run()
        .await?;

    let verifier = verifier.verify().await?;

    // Resolver that builds the predicate fresh (Pred uses Rc, so can't be shared)
    let predicate_resolver = move |name: &str, _indices: &RangeSet<usize>| -> Option<Pred> {
        if name == TEST_PREDICATE {
            Some(make_predicate())
        } else {
            None
        }
    };

    let (output, verifier) = verifier
        .accept_with_predicates(Some(&predicate_resolver))
        .await?;

    verifier.close().await?;

    Ok(output)
}
