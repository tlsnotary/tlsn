use anyhow::Result;

fn init_tracing() {
    use tracing_subscriber::EnvFilter;

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let fut_wasm = tlsn_wasm_test_runner::wasm_server::start().await?;
    let fut_proxy = tlsn_wasm_test_runner::ws::start().await?;
    let fut_tlsn = tlsn_wasm_test_runner::tlsn_fixture::start().await?;
    let fut_server = tlsn_wasm_test_runner::server_fixture::start().await?;

    tokio::spawn(async move {
        futures::future::try_join4(fut_wasm, fut_proxy, fut_tlsn, fut_server)
            .await
            .unwrap()
    });

    let results = tlsn_wasm_test_runner::chrome_driver::run().await?;

    for result in &results {
        println!("{}", result);
    }

    let passed = results.iter().filter(|r| r.passed).count();
    let failed = results.iter().filter(|r| !r.passed).count();

    println!("{} passed, {} failed", passed, failed);

    if results.iter().any(|r| !r.passed) {
        std::process::exit(1);
    }

    Ok(())
}
