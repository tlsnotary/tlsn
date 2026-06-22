//! BoGo (BoringSSL) test shim for TLSNotary's TLS client.
//!
//! BoGo's Go runner acts as the TLS *server* and spawns this binary once per
//! test case, passing the test parameters as command-line flags and connecting
//! it to a localhost port. The shim is the implementation under test.
//!
//! TLSN's TLS client only exists as one half of a 2-party MPC computation, so
//! this shim runs a **full prover+verifier pair in-process** (connected by an
//! in-memory duplex) and exposes a single TCP connection to BoGo. Which party
//! faces BoGo depends on the mode:
//!   - MPC mode:   the prover (TLS leader) holds the connection to BoGo.
//!   - Proxy mode: the verifier (acting as proxy) holds the connection to BoGo.
//!
//! The TLSN-side behaviour (mpc vs proxy, defer-decryption, ...) is supplied by
//! `bogo run` via the `TLSN_BOGO_PROFILE` env var (a JSON-encoded `Bench`), and
//! the trust anchor for BoGo's test certificates via `TLSN_BOGO_CA`.
//!
//! We only need to drive both parties to the `Committed` state: the TLS
//! handshake and application-data exchange *are* the online MPC phase, so once
//! that completes the TLS-level test has run. The post-hoc ZK `prove`/`verify`
//! dance is irrelevant to TLS correctness and is skipped.

use std::{env, process::ExitCode};

use anyhow::{Context, Result, bail};
use futures::{AsyncReadExt, AsyncWriteExt};
use harness_core::bench::Bench;
use harness_executor::spawn;
use tlsn::{
    Session,
    config::{
        prover::ProverConfig,
        tls::TlsClientConfig,
        tls_commit::{mpc::MpcTlsConfig, proxy::ProxyTlsConfig},
        verifier::VerifierConfig,
    },
    connection::{DnsName, ServerName},
    prover::TlsConnection,
    verifier::VerifierCommitStart,
    webpki::{CertificateDer, RootCertStore},
};
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncReadCompatExt;

/// Exit code BoGo interprets as "this feature is unimplemented" (as opposed to
/// a test failure), letting it record the case accordingly.
const UNIMPLEMENTED: u8 = 89;

/// Generous record-size caps. BoGo exchanges only small test payloads, so we
/// don't size these from the profile.
const MAX_DATA: usize = 1 << 16;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    match run().await {
        Ok(code) => code,
        Err(err) => {
            eprintln!("bogo_shim: {err:?}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<ExitCode> {
    let args: Vec<String> = env::args().collect();

    // We only implement the TLS client role; BoGo's server-side tests are out
    // of scope.
    if flag_present(&args, "-server") {
        return Ok(ExitCode::from(UNIMPLEMENTED));
    }

    let port: u16 = flag_value(&args, "-port")
        .context("missing -port flag")?
        .parse()
        .context("invalid -port value")?;
    let server_name = flag_value(&args, "-server-name").unwrap_or_else(|| "example.com".into());

    let bench: Bench = serde_json::from_str(
        &env::var("TLSN_BOGO_PROFILE").context("TLSN_BOGO_PROFILE env var not set")?,
    )
    .context("failed to parse TLSN_BOGO_PROFILE")?;
    let root_store = load_root_store().context("failed to load BoGo trust anchor")?;

    // BoGo listens on loopback and hands us the port.
    let server_socket = TcpStream::connect(("127.0.0.1", port))
        .await
        .context("failed to connect to BoGo runner")?;
    server_socket.set_nodelay(true).ok();
    let server_socket = server_socket.compat();

    // In-process transport between the prover and verifier halves.
    let (prover_io, verifier_io) = tokio::io::duplex(MAX_DATA);

    let result = if bench.proxy {
        run_proxy(
            &bench,
            root_store,
            &server_name,
            prover_io.compat(),
            verifier_io.compat(),
            server_socket,
        )
        .await
    } else {
        run_mpc(
            &bench,
            root_store,
            &server_name,
            prover_io.compat(),
            verifier_io.compat(),
            server_socket,
        )
        .await
    };

    match result {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(err) => {
            // A failed handshake is a legitimate test outcome; BoGo observes the
            // client's alert on the wire. Report it and exit non-zero.
            eprintln!("bogo_shim: session failed: {err:?}");
            Ok(ExitCode::FAILURE)
        }
    }
}

/// MPC mode: the prover holds the TLS connection to BoGo; the verifier is the
/// MPC follower on the in-process transport.
async fn run_mpc<P, V, S>(
    bench: &Bench,
    root_store: RootCertStore,
    server_name: &str,
    prover_io: P,
    verifier_io: V,
    server_socket: S,
) -> Result<()>
where
    P: futures::AsyncRead + futures::AsyncWrite + Send + Unpin + 'static,
    V: futures::AsyncRead + futures::AsyncWrite + Send + Unpin + 'static,
    S: futures::AsyncRead + futures::AsyncWrite + Send + Unpin + 'static,
{
    // Prover.
    let mut prover_session = Session::new(prover_io);
    let prover = prover_session.new_prover(ProverConfig::builder().build()?)?;
    let (prover_driver, prover_handle) = prover_session.split();
    let _prover_driver = spawn(prover_driver);

    let mut commit = MpcTlsConfig::builder().max_sent_data(MAX_DATA);
    commit = commit.defer_decryption_from_start(bench.defer_decryption);
    if !bench.defer_decryption {
        commit = commit.max_recv_data_online(MAX_DATA);
    }
    let commit = commit.max_recv_data(MAX_DATA).build()?;

    let prover = prover.commit(commit).await?;
    let (conn, prover) = prover.connect(tls_client_config(server_name, &root_store)?, server_socket)?;

    // Verifier (MPC follower).
    let verifier_fut = run_verifier(verifier_io, root_store, None::<S>);

    let prover_fut = async move {
        prover.into_future().await?;
        prover_handle.close();
        Ok::<(), anyhow::Error>(())
    };

    futures::try_join!(prover_fut, pump(conn), verifier_fut)?;
    Ok(())
}

/// Proxy mode: the verifier holds the TLS connection to BoGo; the prover speaks
/// to the verifier over the in-process transport.
async fn run_proxy<P, V, S>(
    _bench: &Bench,
    root_store: RootCertStore,
    server_name: &str,
    prover_io: P,
    verifier_io: V,
    server_socket: S,
) -> Result<()>
where
    P: futures::AsyncRead + futures::AsyncWrite + Send + Unpin + 'static,
    V: futures::AsyncRead + futures::AsyncWrite + Send + Unpin + 'static,
    S: futures::AsyncRead + futures::AsyncWrite + Send + Unpin + 'static,
{
    let mut prover_session = Session::new(prover_io);
    let prover = prover_session.new_prover(ProverConfig::builder().build()?)?;
    let (prover_driver, prover_handle) = prover_session.split();
    let _prover_driver = spawn(prover_driver);

    let commit = ProxyTlsConfig::builder()
        .server_name(DnsName::try_from(server_name)?)
        .build()?;
    let prover = prover.commit(commit).await?;
    let (conn, prover) = prover.connect(tls_client_config(server_name, &root_store)?)?;

    // Verifier acts as the proxy and holds the server connection.
    let verifier_fut = run_verifier(verifier_io, root_store, Some(server_socket));

    let prover_fut = async move {
        prover.into_future().await?;
        prover_handle.close();
        Ok::<(), anyhow::Error>(())
    };

    futures::try_join!(prover_fut, pump(conn), verifier_fut)?;
    Ok(())
}

/// Drives the verifier to the `Committed` state. In proxy mode `server_socket`
/// is `Some` and is consumed by the proxy `run`; in MPC mode it is `None`.
async fn run_verifier<V, S>(
    verifier_io: V,
    root_store: RootCertStore,
    server_socket: Option<S>,
) -> Result<()>
where
    V: futures::AsyncRead + futures::AsyncWrite + Send + Unpin + 'static,
    S: futures::AsyncRead + futures::AsyncWrite + Send + Unpin + 'static,
{
    let mut session = Session::new(verifier_io);
    let verifier = session.new_verifier(VerifierConfig::builder().root_store(root_store).build()?)?;
    let (driver, handle) = session.split();
    let _driver = spawn(driver);

    match verifier.commit().await? {
        VerifierCommitStart::Mpc(verifier) => {
            verifier.accept().await?.run().await?;
        }
        VerifierCommitStart::Proxy(verifier) => {
            let server_socket = server_socket
                .context("proxy verifier requires a server socket, but profile is mpc")?;
            verifier.accept().await?.run(server_socket).await?;
        }
    }

    handle.close();
    Ok(())
}

/// Implements BoGo's default shim contract: echo back whatever the runner sends
/// over the established TLS connection until it closes.
async fn pump(mut conn: TlsConnection) -> Result<()> {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = conn.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        conn.write_all(&buf[..n]).await?;
    }
    conn.close().await?;
    Ok(())
}

fn tls_client_config(server_name: &str, root_store: &RootCertStore) -> Result<TlsClientConfig> {
    Ok(TlsClientConfig::builder()
        .server_name(ServerName::Dns(DnsName::try_from(server_name)?))
        .root_store(root_store.clone())
        .build()?)
}

/// Loads the PEM trust anchor for BoGo's test certificates from `TLSN_BOGO_CA`.
fn load_root_store() -> Result<RootCertStore> {
    let path = env::var("TLSN_BOGO_CA").context("TLSN_BOGO_CA env var not set")?;
    let pem = std::fs::read(&path).with_context(|| format!("failed to read {path}"))?;
    let certs = rustls_pemfile::certs(&mut pem.as_slice())
        .context("failed to parse PEM certificates")?;
    if certs.is_empty() {
        bail!("no certificates found in {path}");
    }
    Ok(RootCertStore {
        roots: certs.into_iter().map(CertificateDer).collect(),
    })
}

fn flag_value(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

fn flag_present(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}
