//! A Verifier without memory profiling.

use tlsn_benches::verifier_main::verifier_main;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    verifier_main(false).await
}
