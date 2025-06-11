use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    harness_runner::wasm_server::main().await
}
