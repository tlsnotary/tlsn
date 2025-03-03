mod chrome_driver;
mod wasm_server;
mod ws_proxy;

use crate::{
    runner::server_fixture,
    test::{BrowserTestConfig, TestConfig, TestOutput},
    VerifierProvider, DEFAULT_SERVER_IP, DEFAULT_SERVER_PORT, DEFAULT_WS_PORT,
};
use anyhow::{anyhow, Result};
use chromiumoxide::{Browser, Page};
use futures::TryFutureExt;

use crate::bench::{bench_verifier, BenchConfig, BrowserBenchConfig, Metrics};

pub struct BrowserRunner {
    state: State,
}

impl BrowserRunner {
    pub fn new() -> Self {
        Self { state: State::Init }
    }

    pub async fn start(&mut self) -> Result<()> {
        tokio::spawn(wasm_server::start());
        tokio::spawn(ws_proxy::start());
        tokio::spawn(server_fixture::start());

        let (browser, page) = chrome_driver::start_browser().await?;

        page.evaluate(
            r#"
                (async () => {{
                    return await window.worker.init();
                }})();
            "#,
        )
        .await?;

        self.state = State::Running { browser, page };

        Ok(())
    }

    pub async fn run_test(&self, config: &TestConfig) -> Result<TestOutput> {
        let State::Running { page, .. } = &self.state else {
            return Err(anyhow!("runner not started"));
        };

        let config = BrowserTestConfig {
            test: config.clone(),
            proxy_addr: (DEFAULT_SERVER_IP.to_string(), DEFAULT_WS_PORT),
            server_addr: (DEFAULT_SERVER_IP.to_string(), DEFAULT_SERVER_PORT),
        };

        let config = serde_json::to_string(&config)?;
        page.evaluate(format!(
            r#"
                (async () => {{
                    const config = JSON.parse('{config}');
                    const prover = window.worker.runTestProver(config);
                    const verifier = window.worker.runTestVerifier(config);
                    await Promise.all([prover, verifier]);
                }})();
            "#
        ))
        .await?;

        Ok(TestOutput {
            passed: true,
            time: 0,
            timed_out: false,
        })
    }

    pub async fn run_bench(&self, bench: &BenchConfig) -> Result<Metrics> {
        let State::Running { page, .. } = &self.state else {
            return Err(anyhow!("browser not started"));
        };

        let mut verifier_provider = VerifierProvider::new(DEFAULT_SERVER_IP).await?;

        let config = BrowserBenchConfig {
            proxy_addr: (DEFAULT_SERVER_IP.to_string(), DEFAULT_WS_PORT),
            verifier_addr: verifier_provider.addr(),
            server_addr: (DEFAULT_SERVER_IP.to_string(), DEFAULT_SERVER_PORT),
            bench: bench.clone(),
        };

        let prover_task = async {
            let config = serde_json::to_string(&config)?;
            page.evaluate(format!(
                r#"
                    (async () => {{
                        const config = JSON.parse('{config}');
                        return await window.worker.runBench(config);
                    }})();
                "#
            ))
            .await?
            .into_value()
            .map_err(anyhow::Error::from)
        };

        let verifier_task = {
            let bench = bench.clone();
            tokio::spawn(async move { bench_verifier(&mut verifier_provider, &bench).await })
                .map_err(anyhow::Error::from)
        };

        let (metrics, _) = tokio::try_join!(prover_task, verifier_task)?;

        Ok(metrics)
    }

    pub async fn stop(&mut self) -> Result<()> {
        match &mut self.state {
            State::Running { browser, .. } => {
                browser.close().await?;
                browser.wait().await?;
            }
            _ => {}
        }

        self.state = State::Done;

        Ok(())
    }
}

enum State {
    Init,
    Running { browser: Browser, page: Page },
    Done,
}
