//! A Prover with memory profiling.

use tlsn_benches::prover_main::prover_main;

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if cfg!(feature = "browser-bench") {
        // Memory profiling is not compatible with browser benches.
        return Ok(());
    }
    prover_main(true).await
}
