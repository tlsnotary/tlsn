//! BoGo shim entry point. The runner launches this binary per test case; see
//! the `tlsn_tls_conformance` crate docs for the architecture and exit-code
//! protocol.

use std::process::exit;

use tlsn_tls_conformance::{Outcome, log_skip, parse, run};

fn main() {
    // Opt-in tracing for debugging a single test (`RUST_LOG=debug`).
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .try_init();

    let args: Vec<String> = std::env::args().skip(1).collect();

    // The runner probes split-handshake support before generating tests by
    // running the shim with this flag and reading stdout. We don't support the
    // out-of-process handshaker, so answer "No" and exit cleanly.
    if args.iter().any(|a| a == "-is-handshaker-supported") {
        println!("No");
        exit(0);
    }

    let opts = match parse(&args) {
        Outcome::Run(opts) => opts,
        Outcome::Skip(reason) => {
            log_skip(&reason);
            exit(89);
        }
        Outcome::Error(msg) => {
            eprintln!("bogo_shim argument error: {msg}");
            exit(1);
        }
    };

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");

    match rt.block_on(run(&opts)) {
        Ok(()) => exit(0),
        Err(e) => {
            eprintln!("bogo_shim error: {e:#}");
            exit(1)
        }
    }
}
