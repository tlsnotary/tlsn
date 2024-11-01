//! A Prover without memory profiling.

use tlsn_benches::prover_main::prover_main;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    prover_main(false).await
}
