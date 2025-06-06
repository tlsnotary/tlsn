#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    harness_runner::main().await
}
