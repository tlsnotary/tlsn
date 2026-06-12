//! BoGo conformance-suite orchestrator.
//!
//! Two subcommands:
//!
//! ```text
//! bogo fetch                      # clone + build the Go BoGo runner (needs git, go)
//! bogo run [--workers N] [glob…]  # build the shim, run the suite, tally results
//! ```
//!
//! `run` builds `bogo_shim` with the same profile as this binary, locates it
//! next to itself in the target directory, and invokes the runner with the
//! right flags. Test selectors are `filepath.Match` globs (semicolon-joined for
//! the runner); with none, the whole suite runs. Exits non-zero if any test
//! failed (unimplemented/skipped tests don't count).

use std::{
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio, exit},
};

use anyhow::{Context, Result, bail};

/// Tested commit on the `rustls-testing` branch of `rustls/boringssl` (the same
/// snapshot rustls tests against).
const RUNNER_COMMIT: &str = "b6a09c71d983cf1ad7b729a7b1b287064bc6fae0";

/// Default runner worker count. Each shim runs a full multi-threaded MPC
/// executor, so high parallelism oversubscribes the CPU and handshakes start
/// missing the runner's per-connection timeout.
const DEFAULT_WORKERS: usize = 2;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("fetch") => fetch(),
        Some("run") => run_suite(&args[1..]),
        _ => {
            eprintln!(
                "usage:\n  bogo fetch\n  bogo run [--workers N] [test-glob …]\n\n\
                 test-globs are filepath.Match patterns, e.g. 'VersionNegotiation-Client-TLS12-*'"
            );
            exit(2);
        }
    };

    if let Err(e) = result {
        eprintln!("bogo: {e:#}");
        exit(1);
    }
}

/// `bogo fetch` — clone and build the Go runner into `bogo/boringssl`.
fn fetch() -> Result<()> {
    let src = bogo_dir().join("boringssl");

    if !src.join(".git").exists() {
        if src.exists() {
            std::fs::remove_dir_all(&src).ok();
        }
        // Sparse, blobless clone: only the runner and its build metadata.
        run_cmd(
            Command::new("git")
                .args(["clone", "--sparse", "--filter=blob:none"])
                .arg("https://github.com/rustls/boringssl")
                .arg(&src),
            "git clone",
        )?;
    }

    // --skip-checks: the set includes individual files (go.mod/go.sum), which
    // cone mode otherwise rejects as "not a directory".
    run_cmd(
        Command::new("git").current_dir(&src).args([
            "sparse-checkout",
            "set",
            "--skip-checks",
            "go.mod",
            "go.sum",
            "ssl/test/runner",
            "util/testresult",
        ]),
        "git sparse-checkout",
    )?;
    run_cmd(
        Command::new("git")
            .current_dir(&src)
            .args(["fetch", "--depth=1", "origin", RUNNER_COMMIT]),
        "git fetch",
    )?;
    run_cmd(
        Command::new("git")
            .current_dir(&src)
            .args(["checkout", "-q", RUNNER_COMMIT]),
        "git checkout",
    )?;

    let runner_dir = src.join("ssl/test/runner");
    // `go test -c` compiles the runner into a standalone `runner.test` binary.
    run_cmd(
        Command::new("go").current_dir(&runner_dir).args(["test", "-c"]),
        "go test -c",
    )?;

    eprintln!("built BoGo runner: {}", runner_dir.join("runner.test").display());
    Ok(())
}

/// `bogo run` — build the shim, run the suite, tally results, set exit code.
fn run_suite(args: &[String]) -> Result<()> {
    let runner_dir = bogo_dir().join("boringssl/ssl/test/runner");
    let runner = runner_dir.join("runner.test");
    if !runner.exists() {
        bail!(
            "runner not found at {} — run `bogo fetch` first (needs git + go)",
            runner.display()
        );
    }

    let (workers, globs) = parse_run_args(args)?;
    let shim = build_shim()?;
    let config = bogo_dir().join("config.json");

    let mut cmd = Command::new(&runner);
    cmd.current_dir(&runner_dir) // the runner resolves fixtures relative to here
        .arg("-shim-path")
        .arg(&shim)
        .arg("-shim-config")
        .arg(&config)
        .arg("-num-workers")
        .arg(workers.to_string())
        .args(["-pipe", "-allow-unimplemented"]);
    if !globs.is_empty() {
        cmd.arg("-test").arg(globs.join(";"));
    }

    let (passed, failed, skipped) = run_and_tally(cmd)?;
    eprintln!("\nBoGo: {passed} passed, {failed} failed, {skipped} skipped");
    if failed > 0 {
        exit(1);
    }
    Ok(())
}

/// Parses `[--workers N] [glob …]`.
fn parse_run_args(args: &[String]) -> Result<(usize, Vec<String>)> {
    let mut workers = DEFAULT_WORKERS;
    let mut globs = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--workers" => {
                let v = args.get(i + 1).context("--workers needs a value")?;
                workers = v.parse().context("--workers must be a number")?;
                i += 2;
            }
            glob => {
                globs.push(glob.to_string());
                i += 1;
            }
        }
    }
    Ok((workers, globs))
}

/// Builds `bogo_shim` with the same profile as this binary and returns its path
/// (next to this executable in the target directory).
fn build_shim() -> Result<PathBuf> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let release = !cfg!(debug_assertions);

    let mut cmd = Command::new(&cargo);
    cmd.args(["build", "-p", "tlsn-tls-conformance", "--bin", "bogo_shim"]);
    if release {
        cmd.arg("--release");
    }
    run_cmd(&mut cmd, "cargo build bogo_shim")?;

    let dir = std::env::current_exe()
        .context("current_exe")?
        .parent()
        .context("executable has no parent directory")?
        .to_path_buf();
    let shim = dir.join("bogo_shim");
    if !shim.exists() {
        bail!("built shim not found at {}", shim.display());
    }
    Ok(shim)
}

/// Runs the runner, streaming its output through while counting dispositions.
fn run_and_tally(mut cmd: Command) -> Result<(usize, usize, usize)> {
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .context("spawn runner")?;

    let stdout = child.stdout.take().context("runner stdout")?;
    let (mut passed, mut failed, mut skipped) = (0, 0, 0);
    for line in BufReader::new(stdout).lines() {
        let line = line.context("read runner output")?;
        println!("{line}");
        if line.starts_with("PASSED (") {
            passed += 1;
        } else if line.starts_with("FAILED (") {
            failed += 1;
        } else if line.starts_with("UNIMPLEMENTED (") {
            skipped += 1;
        }
    }
    child.wait().context("wait for runner")?;
    Ok((passed, failed, skipped))
}

/// The crate's `bogo/` directory (runner sources, config, build artifacts).
fn bogo_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("bogo")
}

/// Spawns `cmd` with inherited stdio and fails unless it exits successfully.
fn run_cmd(cmd: &mut Command, what: &str) -> Result<()> {
    let status: ExitStatus = cmd.status().with_context(|| format!("failed to run {what}"))?;
    if !status.success() {
        bail!("{what} failed with {status}");
    }
    Ok(())
}
