//! `bogo install` / `bogo run` orchestration.
//!
//! BoGo is BoringSSL's TLS protocol test suite. Its Go runner acts as the TLS
//! peer and spawns our `bogo_shim` binary once per test case. This module
//! fetches/builds that runner (`install`) and drives it against the shim once
//! per configured TLSN profile (`run`).
//!
//! None of the harness's virtual-network / executor machinery is involved: the
//! shim runs a self-contained in-process prover+verifier pair.

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use harness_core::bench::BenchItems;

use crate::cli::BogoCommand;

/// GitHub mirror of BoringSSL.
const BORINGSSL_URL: &str = "https://github.com/google/boringssl";

/// BoringSSL revision to check out. Override with the `BORINGSSL_REV` env var.
/// TODO: pin this to a known-good commit once the suite is green; for now we
/// track `master` and log the resolved commit so it can be pinned later.
const BORINGSSL_DEFAULT_REV: &str = "master";

pub async fn main(command: BogoCommand) -> Result<()> {
    match command {
        BogoCommand::Install {} => install(),
        BogoCommand::Run { config, test } => run(&config, test.as_deref()),
    }
}

/// Directory holding the BoringSSL checkout and the compiled runner, placed
/// next to the runner binary (alongside `bogo_shim`, `server-fixture`, ...).
fn cache_dir() -> Result<PathBuf> {
    let exe = std::env::current_exe()?;
    Ok(exe
        .parent()
        .context("runner binary has no parent directory")?
        .join(".bogo"))
}

fn shim_path() -> Result<PathBuf> {
    let exe = std::env::current_exe()?;
    Ok(exe
        .parent()
        .context("runner binary has no parent directory")?
        .join("bogo_shim"))
}

fn runner_dir(cache: &Path) -> PathBuf {
    cache.join("boringssl/ssl/test/runner")
}

fn runner_bin(cache: &Path) -> PathBuf {
    cache.join("bogo_runner")
}

/// Trust anchor presented by BoGo's server in client tests.
/// TODO: confirm this is the correct file/format for the BoGo certs in use.
fn ca_path(cache: &Path) -> PathBuf {
    cache.join("boringssl/ssl/test/runner/cert.pem")
}

fn install() -> Result<()> {
    ensure_go()?;

    let cache = cache_dir()?;
    fs::create_dir_all(&cache)?;
    let src = cache.join("boringssl");

    if !src.exists() {
        println!("cloning BoringSSL into {}", src.display());
        duct::cmd!("git", "clone", BORINGSSL_URL, &src)
            .run()
            .context("git clone of BoringSSL failed")?;
    }

    let rev = std::env::var("BORINGSSL_REV").unwrap_or_else(|_| BORINGSSL_DEFAULT_REV.to_string());
    duct::cmd!("git", "-C", &src, "fetch", "origin", &rev)
        .run()
        .context("git fetch failed")?;
    duct::cmd!("git", "-C", &src, "checkout", &rev)
        .run()
        .context("git checkout failed")?;

    let resolved = duct::cmd!("git", "-C", &src, "rev-parse", "HEAD")
        .read()
        .context("git rev-parse failed")?;
    println!("BoringSSL at commit {}", resolved.trim());

    println!("building BoGo runner");
    duct::cmd!("go", "test", "-c", "-o", runner_bin(&cache), ".")
        .dir(runner_dir(&cache))
        .run()
        .context("`go test -c` of the BoGo runner failed")?;

    println!("done. runner: {}", runner_bin(&cache).display());
    Ok(())
}

fn run(config: &Path, test: Option<&str>) -> Result<()> {
    let cache = cache_dir()?;
    let runner = runner_bin(&cache);
    if !runner.exists() {
        bail!(
            "BoGo runner not found at {}. Run `runner bogo install` first.",
            runner.display()
        );
    }

    let shim = shim_path()?;
    if !shim.exists() {
        bail!(
            "bogo_shim not found at {}. Build the harness first (./build.sh).",
            shim.display()
        );
    }

    let ca = ca_path(&cache);
    let items: BenchItems = toml::from_str(
        &fs::read_to_string(config)
            .with_context(|| format!("failed to read config {}", config.display()))?,
    )
    .with_context(|| format!("failed to parse config {}", config.display()))?;
    // One run per profile entry (samples forced to 1).
    let profiles = items.to_benches(1, true);

    let mut any_failed = false;
    for profile in profiles {
        let label = profile
            .name
            .clone()
            .or_else(|| profile.group.clone())
            .unwrap_or_else(|| "default".to_string());
        println!("\n=== BoGo suite: profile `{label}` (proxy={}) ===", profile.proxy);

        let json = serde_json::to_string(&profile)?;

        let mut args: Vec<String> = vec![
            "-shim-path".into(),
            shim.display().to_string(),
            "-allow-unimplemented".into(),
        ];
        if let Some(test) = test {
            // TODO: confirm the runner's name-filter flag.
            args.push("-test".into());
            args.push(test.into());
        }

        let status = duct::cmd(&runner, &args)
            .dir(runner_dir(&cache))
            .env("TLSN_BOGO_PROFILE", &json)
            .env("TLSN_BOGO_CA", &ca)
            .unchecked()
            .run()
            .context("failed to run the BoGo runner")?;

        if !status.status.success() {
            any_failed = true;
            eprintln!("profile `{label}`: BoGo reported failures");
        }
    }

    if any_failed {
        bail!("one or more BoGo profiles reported failures");
    }
    Ok(())
}

fn ensure_go() -> Result<()> {
    duct::cmd!("go", "version")
        .stdout_null()
        .stderr_null()
        .run()
        .context("`go` toolchain not found on PATH; install Go to build the BoGo runner")?;
    Ok(())
}
