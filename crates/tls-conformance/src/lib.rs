//! BoGo shim logic for the TLSNotary TLS client.
//!
//! BoGo is BoringSSL's TLS protocol conformance suite. Its Go "runner" acts as
//! the peer (a TLS *server* when testing a client) and, for each test case,
//! launches a "shim" binary with command-line flags describing the scenario.
//! The shim connects back to the runner over TCP, drives a TLS client handshake
//! with the library under test, and reports the outcome via its exit code:
//!
//! * `0` — handshake/exchange succeeded.
//! * `89` — feature not implemented; the runner skips it (and
//!   `-allow-unimplemented` ignores it entirely).
//! * other — failure; an error string is written to stderr.
//!
//! TLSNotary's "client" is two parties (prover + verifier) running an MPC-TLS
//! protocol. The shim runs both in-process, wired together over an in-memory
//! duplex, with the prover connecting to the runner as the TLS server peer.
//!
//! ## Scope
//!
//! BoGo tests the TLS protocol; TLSNotary's attestation/disclosure phase is out
//! of scope. We run only the handshake and record-layer exchange
//! (`prover.connect` + future; verifier `commit` -> `run`) and never call
//! `prove`/`verify`.
//!
//! Note the MPC client *does* verify the server certificate's **name** during
//! the handshake (so [`Options::host_name`] must match the cert the runner
//! presents); only chain-of-trust validation is deferred to the skipped prove
//! phase.
//!
//! TLSNotary's MPC-TLS currently supports **TLS 1.2** with the two
//! `ECDHE_{RSA,ECDSA}_WITH_AES_128_GCM_SHA256` cipher suites and client
//! authentication; no TLS 1.3, resumption, or renegotiation. Features outside
//! this surface are reported as unimplemented (`89`). [`parse`] is where the
//! "skip vs run-and-maybe-fail" split lives — the main knob to tune as support
//! grows.

mod flags;

use std::{str::FromStr, time::Duration};

use anyhow::Context as _;
use tlsn::{
    Session,
    config::{
        prover::ProverConfig, tls::TlsClientConfig, tls_commit::mpc::MpcTlsConfig,
        verifier::VerifierConfig,
    },
    connection::{DnsName, ServerName},
    prover::TlsConnection,
    verifier::VerifierCommitStart,
    webpki::{CertificateDer, PrivateKeyDer, RootCertStore},
};
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncReadCompatExt;

use crate::flags::{BOOL_FLAGS, FlagToken, UNSUPPORTED_FLAGS, VALUE_FLAGS, classify_prefix};

/// TLS 1.2 wire version (`0x0303`). BoGo passes `-min/-max-version` as the
/// decimal of the wire version.
const TLS12: u16 = 0x0303;

/// Buffer for the prover <-> verifier in-memory transport (16 MiB).
const SESSION_BUF: usize = 1 << 24;

/// Read buffer for the post-handshake echo loop.
const ECHO_BUF: usize = 512;

/// Per-connection wall-clock cap. The runner has its own per-test timeout, but
/// this prevents a wedged MPC handshake from hanging the shim indefinitely.
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(60);

/// The decision produced by parsing the runner's argv.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Run the scenario with these options.
    Run(Options),
    /// Skip the scenario (exit `89`); the string is a coarse reason for tallying.
    Skip(String),
    /// The arguments were malformed (exit non-zero with this message).
    Error(String),
}

/// Parsed subset of the BoGo flags this shim understands.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Options {
    port: u16,
    shim_id: u64,
    ipv6: bool,
    host_name: Option<String>,
    trust_cert: Option<String>,
    /// Client-authentication certificate chain and matching private key (PEM).
    cert_file: Option<String>,
    key_file: Option<String>,
    shim_writes_first: bool,
    resume_count: usize,
    min_version: Option<u16>,
    max_version: Option<u16>,
}

/// Parses the runner's argv into an [`Outcome`].
///
/// Unknown flags, flags in [`flags::UNSUPPORTED_FLAGS`], and unsupported
/// connection-scope prefixes resolve to [`Outcome::Skip`]; malformed values to
/// [`Outcome::Error`]; everything else to [`Outcome::Run`]. This function is
/// pure (no I/O, no process exit) so it can be unit-tested.
pub fn parse(args: &[String]) -> Outcome {
    let mut opts = Options::default();
    let mut i = 0;
    while i < args.len() {
        let raw = args[i].as_str();
        i += 1;

        let flag = match classify_prefix(raw) {
            FlagToken::Skip => return Outcome::Skip("on-resume/retry/handshaker-prefix".into()),
            FlagToken::Inner(inner) => inner,
        };

        if UNSUPPORTED_FLAGS.contains(&flag) {
            return Outcome::Skip(format!("unsupported-flag:{flag}"));
        }

        let value = if VALUE_FLAGS.contains(&flag) {
            let v = args.get(i).cloned();
            i += 1;
            v
        } else if BOOL_FLAGS.contains(&flag) {
            None
        } else {
            return Outcome::Skip(format!("unknown-flag:{flag}"));
        };

        if let Err(msg) = apply(flag, value, &mut opts) {
            return Outcome::Error(msg);
        }
    }

    // Gates that depend on parsed values rather than a single flag.
    if opts.resume_count > 0 {
        return Outcome::Skip("resume-count>0".into()); // no resumption support
    }
    if matches!(opts.min_version, Some(v) if v > TLS12) {
        return Outcome::Skip("min-version>TLS1.2".into()); // requires TLS 1.3+
    }
    if matches!(opts.max_version, Some(v) if v < TLS12) {
        return Outcome::Skip("max-version<TLS1.2".into()); // requires TLS 1.1-
    }

    Outcome::Run(opts)
}

/// Applies a recognized flag, returning an error message for malformed values.
/// Recognized-but-irrelevant flags are accepted and ignored.
fn apply(flag: &str, value: Option<String>, opts: &mut Options) -> Result<(), String> {
    match flag {
        "-port" => opts.port = parse_value(flag, value)?,
        "-shim-id" => opts.shim_id = parse_value(flag, value)?,
        "-ipv6" => opts.ipv6 = true,
        "-host-name" => opts.host_name = value,
        "-trust-cert" => opts.trust_cert = value,
        "-cert-file" => opts.cert_file = value,
        "-key-file" => opts.key_file = value,
        "-shim-writes-first" => opts.shim_writes_first = true,
        "-resume-count" => opts.resume_count = parse_value(flag, value)?,
        "-min-version" => opts.min_version = Some(parse_value(flag, value)?),
        "-max-version" => opts.max_version = Some(parse_value(flag, value)?),
        _ => {}
    }
    Ok(())
}

/// Parses a value-flag's argument, mapping the absent/unparsable cases to a
/// human-readable error.
fn parse_value<T: FromStr>(flag: &str, value: Option<String>) -> Result<T, String> {
    let v = value.ok_or_else(|| format!("missing value for {flag}"))?;
    v.parse::<T>()
        .map_err(|_| format!("invalid value for {flag}: {v}"))
}

/// Appends a skip `reason` to the file named by `BOGO_NYI_LOG`, if set — a cheap
/// way to tally *why* tests are being skipped across a run.
pub fn log_skip(reason: &str) {
    if let Some(path) = std::env::var_os("BOGO_NYI_LOG")
        && let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
    {
        use std::io::Write as _;
        let _ = writeln!(f, "{reason}");
    }
}

/// Connects to the runner and drives one TLS client connection, under a
/// wall-clock cap.
pub async fn run(opts: &Options) -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt as _;

    let addr = if opts.ipv6 {
        format!("[::1]:{}", opts.port)
    } else {
        format!("127.0.0.1:{}", opts.port)
    };

    let work = async {
        let mut tcp = TcpStream::connect(&addr).await.context("connect to runner")?;
        let _ = tcp.set_nodelay(true);
        // The runner expects the shim id as a little-endian u64 prefix on the
        // connection, before the TLS handshake begins.
        tcp.write_all(&opts.shim_id.to_le_bytes())
            .await
            .context("write shim id")?;
        run_connection(opts, tcp).await
    };

    match tokio::time::timeout(CONNECTION_TIMEOUT, work).await {
        Ok(result) => result,
        Err(_) => anyhow::bail!("connection timed out"),
    }
}

/// Runs the prover and verifier (the two halves of the MPC-TLS client) against
/// the runner over `tcp`, performing the handshake and a best-effort data
/// exchange.
async fn run_connection(opts: &Options, tcp: TcpStream) -> anyhow::Result<()> {
    let root_store = match &opts.trust_cert {
        Some(path) => RootCertStore {
            roots: load_certs(path)?,
        },
        // Unused: chain-of-trust validation happens in the (skipped) prove phase.
        None => RootCertStore { roots: vec![] },
    };

    // The MPC client verifies the cert name during the handshake, so this must
    // match the cert the runner presents. Its default leaf cert has SAN "test".
    let name = opts.host_name.as_deref().unwrap_or("test");
    let server_name = match DnsName::try_from(name) {
        Ok(dns) => ServerName::Dns(dns),
        Err(_) => return Err(anyhow::anyhow!("server name is not a DNS name: {name}")),
    };

    let shim_writes_first = opts.shim_writes_first;

    let (prover_socket, verifier_socket) = tokio::io::duplex(SESSION_BUF);
    let mut session_p = Session::new(prover_socket.compat());
    let mut session_v = Session::new(verifier_socket.compat());

    let prover = session_p.new_prover(ProverConfig::builder().build()?)?;
    let verifier = session_v.new_verifier(
        VerifierConfig::builder()
            .root_store(root_store.clone())
            .build()?,
    )?;

    let (session_p_driver, session_p_handle) = session_p.split();
    let (session_v_driver, session_v_handle) = session_v.split();
    tokio::spawn(session_p_driver);
    tokio::spawn(session_v_driver);

    // Kept small to stay within the multiplexer's stream limit; larger record
    // counts exhaust it during MPC preprocessing. These mirror the values the
    // `tlsn` integration tests use. Tests that exchange more app data than this
    // budget allows will fail for now (the handshake itself is unaffected).
    let mpc_config = MpcTlsConfig::builder()
        .max_sent_data(1 << 12)
        .max_sent_records(4)
        .max_recv_data(1 << 14)
        .max_recv_records_online(6)
        // BoGo's default exchange has the server write first and expects an
        // immediate echo, which requires decrypting received records online.
        .defer_decryption_from_start(false)
        .build()?;

    let mut tls_builder = TlsClientConfig::builder()
        .server_name(server_name)
        .root_store(root_store);
    // Present a client certificate if the runner gave us one. TLSNotary only
    // sends it when the server actually requests one (CertificateRequest), so
    // this is harmless for tests that don't do client auth.
    if let (Some(cert), Some(key)) = (&opts.cert_file, &opts.key_file) {
        tls_builder = tls_builder.client_auth(load_client_auth(cert, key)?);
    }
    let tls_config = tls_builder.build()?;

    let prover_side = async move {
        let prover = prover.commit(mpc_config).await.context("prover commit")?;
        let (mut conn, prover) = prover
            .connect(tls_config, tcp.compat())
            .context("prover connect")?;
        // Detached on early return below; harmless since the process is
        // short-lived and `run` caps total time.
        let prover_fut = tokio::spawn(prover.into_future());

        do_exchange(&mut conn, shim_writes_first)
            .await
            .context("data exchange")?;

        prover_fut
            .await
            .context("prover task panicked")?
            .context("prover handshake failed")?;
        anyhow::Ok(())
    };

    let verifier_side = async move {
        match verifier.commit().await.context("verifier commit")? {
            VerifierCommitStart::Mpc(verifier) => {
                verifier
                    .accept()
                    .await
                    .context("verifier accept")?
                    .run()
                    .await
                    .context("verifier run")?;
            }
            VerifierCommitStart::Proxy(_) => anyhow::bail!("unexpected proxy-mode verifier"),
        }
        anyhow::Ok(())
    };

    let (prover_result, verifier_result) = tokio::join!(prover_side, verifier_side);

    session_p_handle.close();
    session_v_handle.close();

    prover_result?;
    verifier_result?;
    Ok(())
}

/// Performs the post-handshake application-data exchange.
///
/// BoGo's contract: read each test message and write it back with every byte
/// XOR'd by `0xff` (see `expectedReply` in the runner). Handshake-only tests
/// send no data and close, surfacing here as an immediate EOF. With
/// `-shim-writes-first` the shim writes a fixed greeting first (matching
/// BoringSSL's reference shim).
async fn do_exchange(conn: &mut TlsConnection, shim_writes_first: bool) -> anyhow::Result<()> {
    use futures::{AsyncReadExt, AsyncWriteExt};

    if shim_writes_first {
        conn.write_all(b"hello").await?;
    }

    let mut buf = [0u8; ECHO_BUF];
    loop {
        let n = conn.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        for byte in &mut buf[..n] {
            *byte ^= 0xff;
        }
        conn.write_all(&buf[..n]).await?;
    }

    conn.close().await?;
    Ok(())
}

/// Reads a PEM file into a chain of DER-encoded certificates.
fn load_certs(path: &str) -> anyhow::Result<Vec<CertificateDer>> {
    let pem = std::fs::read(path).with_context(|| format!("read certs {path}"))?;
    let mut reader = std::io::BufReader::new(&pem[..]);
    Ok(rustls_pemfile::certs(&mut reader)
        .with_context(|| format!("parse cert PEM {path}"))?
        .into_iter()
        .map(CertificateDer)
        .collect())
}

/// Loads a PEM certificate chain and private key for client authentication.
fn load_client_auth(
    cert_path: &str,
    key_path: &str,
) -> anyhow::Result<(Vec<CertificateDer>, PrivateKeyDer)> {
    let certs = load_certs(cert_path)?;
    let key_pem = std::fs::read(key_path).with_context(|| format!("read key {key_path}"))?;
    let key = PrivateKeyDer::from_pem_slice(&key_pem)
        .map_err(|e| anyhow::anyhow!("parse client key PEM {key_path}: {e}"))?;
    Ok((certs, key))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn value_flag_consumes_next_arg() {
        let Outcome::Run(opts) = parse(&argv(&["-port", "1234", "-shim-id", "7", "-ipv6"])) else {
            panic!("expected Run");
        };
        assert_eq!(opts.port, 1234);
        assert_eq!(opts.shim_id, 7);
        assert!(opts.ipv6);
    }

    #[test]
    fn host_name_and_cert_flags_captured() {
        let Outcome::Run(opts) = parse(&argv(&[
            "-host-name", "example.com", "-cert-file", "c.pem", "-key-file", "k.pem",
        ])) else {
            panic!("expected Run");
        };
        assert_eq!(opts.host_name.as_deref(), Some("example.com"));
        assert_eq!(opts.cert_file.as_deref(), Some("c.pem"));
        assert_eq!(opts.key_file.as_deref(), Some("k.pem"));
    }

    #[test]
    fn unknown_flag_skips() {
        assert_eq!(
            parse(&argv(&["-no-such-flag"])),
            Outcome::Skip("unknown-flag:-no-such-flag".into())
        );
    }

    #[test]
    fn unsupported_flag_skips() {
        assert_eq!(
            parse(&argv(&["-server"])),
            Outcome::Skip("unsupported-flag:-server".into())
        );
    }

    #[test]
    fn resume_and_retry_prefixes_skip() {
        assert_eq!(
            parse(&argv(&["-on-resume-shim-writes-first"])),
            Outcome::Skip("on-resume/retry/handshaker-prefix".into())
        );
    }

    #[test]
    fn shim_and_initial_prefixes_are_stripped_and_applied() {
        let Outcome::Run(opts) = parse(&argv(&["-on-initial-shim-writes-first"])) else {
            panic!("expected Run");
        };
        assert!(opts.shim_writes_first);
    }

    #[test]
    fn resume_count_gates() {
        assert_eq!(
            parse(&argv(&["-resume-count", "1"])),
            Outcome::Skip("resume-count>0".into())
        );
        // resume-count 0 is fine.
        assert!(matches!(parse(&argv(&["-resume-count", "0"])), Outcome::Run(_)));
    }

    #[test]
    fn version_gates() {
        // 772 = TLS 1.3.
        assert_eq!(
            parse(&argv(&["-min-version", "772"])),
            Outcome::Skip("min-version>TLS1.2".into())
        );
        // 770 = TLS 1.1.
        assert_eq!(
            parse(&argv(&["-max-version", "770"])),
            Outcome::Skip("max-version<TLS1.2".into())
        );
        // A 1.2-inclusive window runs.
        assert!(matches!(
            parse(&argv(&["-min-version", "771", "-max-version", "772"])),
            Outcome::Run(_)
        ));
    }

    #[test]
    fn malformed_value_errors() {
        assert!(matches!(parse(&argv(&["-port", "not-a-number"])), Outcome::Error(_)));
    }

    /// Invariant: an unsupported flag must also be classified, else it would be
    /// treated as "unknown" and the two skip reasons would be ambiguous.
    #[test]
    fn unsupported_flags_are_classified() {
        for flag in UNSUPPORTED_FLAGS {
            assert!(
                BOOL_FLAGS.contains(flag) || VALUE_FLAGS.contains(flag),
                "{flag} is unsupported but not in BOOL_FLAGS or VALUE_FLAGS"
            );
        }
    }

    /// Invariant: a flag cannot be both boolean and value-taking.
    #[test]
    fn bool_and_value_flags_are_disjoint() {
        for flag in BOOL_FLAGS {
            assert!(
                !VALUE_FLAGS.contains(flag),
                "{flag} is in both BOOL_FLAGS and VALUE_FLAGS"
            );
        }
    }
}
