//! Large upload through proxy mode.
//!
//! Regression for a transport close that raced the staging channel: the prover
//! used to close the proxy transport as soon as rustls had no output left,
//! even though `write_tls` had only copied those bytes into the staging channel
//! between the TLS client and the server socket. Uploads that were still being
//! forwarded were truncated, and the peer saw a stream with no `close_notify`.
//!
//! The test sends 10 MiB and then closes the application write side, the way a
//! client would after uploading a large body. The server deliberately pauses
//! before it starts reading, so the upload is still backed up in the staging
//! channel when the client closes. It then counts every byte it consumes; the
//! test fails on any truncation.
//!
//! This needs `tlsn_insecure` because a 10 MiB upload is far too large for a
//! real ZK proof. Run it with:
//!
//! ```text
//! RUSTFLAGS="--cfg tlsn_insecure" \
//!     cargo test -p tlsn --test proxy_large_upload --profile tests-integration
//! ```

#![allow(unexpected_cfgs)]
#![cfg(tlsn_insecure)]

use std::{sync::Arc, time::Duration};

use futures::{AsyncReadExt, AsyncWriteExt};
use futures_rustls::{
    TlsAcceptor,
    pki_types::{CertificateDer as RustlsCert, PrivateKeyDer},
    rustls::ServerConfig,
};
use tls_server_fixture::{CA_CERT_DER, SERVER_CERT_DER, SERVER_DOMAIN, SERVER_KEY_DER};
use tlsn::{
    Session,
    config::{
        prover::ProverConfig, tls::TlsClientConfig, tls_commit::proxy::ProxyTlsConfig,
        verifier::VerifierConfig,
    },
    connection::{DnsName, ServerName},
    verifier::VerifierCommitStart,
    webpki::{CertificateDer, RootCertStore},
};
use tokio::io::DuplexStream;
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};

/// Ten mebibytes. This is deliberately below the prover's 16 MiB staging
/// channel: the whole upload can therefore sit in that channel when the client
/// closes, which is exactly the state that used to be discarded.
const UPLOAD_SIZE: usize = 10 * 1024 * 1024;

/// How long the server waits before reading. Long enough for the client to
/// write and close while the upload is still queued.
const SERVER_READ_DELAY: Duration = Duration::from_millis(500);

fn root_store() -> RootCertStore {
    RootCertStore {
        roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
    }
}

fn tls_client_config() -> TlsClientConfig {
    TlsClientConfig::builder()
        .server_name(ServerName::Dns(SERVER_DOMAIN.try_into().unwrap()))
        .root_store(root_store())
        .build()
        .unwrap()
}

/// Accepts one TLS connection, pauses, then reads until EOF and returns the
/// number of application bytes consumed and whether the close was clean.
async fn delayed_reader(socket: Compat<DuplexStream>) -> (usize, bool) {
    let key = PrivateKeyDer::Pkcs8(SERVER_KEY_DER.into());
    let cert = RustlsCert::from(SERVER_CERT_DER);
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();

    let acceptor = TlsAcceptor::from(Arc::new(config));
    let mut conn = acceptor.accept(socket).await.unwrap();

    tokio::time::sleep(SERVER_READ_DELAY).await;

    let mut buf = vec![0u8; 16 * 1024];
    let mut total = 0;
    let mut clean_close = false;
    loop {
        match conn.read(&mut buf).await {
            Ok(0) => {
                clean_close = true;
                break;
            }
            Err(_) => break,
            Ok(n) => total += n,
        }
    }

    // Let the prover finish cleanly even though its write side is already shut.
    conn.get_mut().1.send_close_notify();
    let _ = conn.flush().await;

    (total, clean_close)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_large_upload_reaches_the_server_before_close() {
    let (p_io, v_io) = tokio::io::duplex(2 << 23);
    let mut p_session = Session::new(p_io.compat());
    let mut v_session = Session::new(v_io.compat());

    let prover = p_session
        .new_prover(ProverConfig::builder().build().unwrap())
        .unwrap();
    let verifier = v_session
        .new_verifier(
            VerifierConfig::builder()
                .root_store(root_store())
                .build()
                .unwrap(),
        )
        .unwrap();

    let (p_driver, p_handle) = p_session.split();
    let (v_driver, v_handle) = v_session.split();
    let p_driver = tokio::spawn(async move {
        let _ = p_driver.await;
    });
    let v_driver = tokio::spawn(async move {
        let _ = v_driver.await;
    });

    let (client_socket, server_socket) = tokio::io::duplex(2 << 20);
    let server_task = tokio::spawn(delayed_reader(server_socket.compat()));

    let proxy_config = ProxyTlsConfig::builder()
        .server_name(DnsName::try_from(SERVER_DOMAIN).unwrap())
        .build()
        .unwrap();

    let prover_fut = async move {
        let prover = prover.commit(proxy_config).await.unwrap();
        let (mut conn, prover) = prover.connect(tls_client_config()).unwrap();
        let prover_task = tokio::spawn(prover.into_future());

        let upload = vec![b'A'; UPLOAD_SIZE];
        conn.write_all(&upload).await.unwrap();
        // Closing the write side sends `close_notify` and asks the prover to
        // close the transport. Everything written above must still be in
        // flight at that point; the prover must drain it first.
        conn.close().await.unwrap();

        // Wait for the server's close so the session can finish.
        let mut sink = Vec::new();
        conn.read_to_end(&mut sink).await.unwrap();

        prover_task.await.unwrap().unwrap()
    };

    let verifier_fut = async move {
        let VerifierCommitStart::Proxy(verifier) = verifier.commit().await.unwrap() else {
            panic!("expected proxy commitment");
        };
        let verifier = verifier.accept().await.unwrap();
        verifier.run(client_socket.compat()).await.unwrap()
    };

    let (prover, verifier, (received, clean_close)) =
        tokio::time::timeout(Duration::from_secs(120), async move {
            let (prover, verifier) = tokio::join!(prover_fut, verifier_fut);
            let received = server_task.await.unwrap();
            (prover, verifier, received)
        })
        .await
        .expect("proxy upload timed out");

    assert_eq!(
        received, UPLOAD_SIZE,
        "the server consumed {received} of {UPLOAD_SIZE} uploaded bytes"
    );
    assert!(
        clean_close,
        "the server must see a clean close_notify, not an abrupt reset"
    );

    prover.close().await.unwrap();
    verifier.close().await.unwrap();

    p_handle.close();
    v_handle.close();
    p_driver.await.unwrap();
    v_driver.await.unwrap();
}
