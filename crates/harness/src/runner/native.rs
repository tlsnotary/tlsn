use std::{
    panic::AssertUnwindSafe,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Result};
use futures::FutureExt;

use crate::{
    runner::server_fixture,
    test::{get_test, TestConfig, TestOutput},
    ProverProvider, VerifierProvider, DEFAULT_SERVER_IP, DEFAULT_SERVER_PORT,
};

use crate::bench::{bench_prover, bench_verifier, BenchConfig, Metrics};

pub struct NativeRunner {
    state: State,
}

impl NativeRunner {
    pub fn new() -> Self {
        Self { state: State::Init }
    }

    pub async fn start(&mut self) -> Result<()> {
        // Prebuild the PRF circuits, they're heavy.
        hmac_sha256::build_circuits().await;

        tokio::spawn(server_fixture::start());

        self.state = State::Running;

        Ok(())
    }

    pub async fn run_test(&self, config: &TestConfig) -> Result<TestOutput> {
        let State::Running = &self.state else {
            return Err(anyhow!("runner not started"));
        };

        let test = get_test(&config.name).unwrap();

        let mut verifier_provider = VerifierProvider::new(DEFAULT_SERVER_IP).await?;
        let mut prover_provider = ProverProvider::new(
            (DEFAULT_SERVER_IP.to_string(), DEFAULT_SERVER_PORT),
            verifier_provider.addr(),
        );

        let start = Instant::now();
        let timeout = config.timeout;

        let prover_task = tokio::spawn(async move {
            tokio::time::timeout(
                Duration::from_secs(timeout),
                AssertUnwindSafe((test.prover)(&mut prover_provider)).catch_unwind(),
            )
            .await
        });
        let verifier_task = tokio::spawn(async move {
            tokio::time::timeout(
                Duration::from_secs(timeout),
                AssertUnwindSafe((test.verifier)(&mut verifier_provider)).catch_unwind(),
            )
            .await
        });

        let (prover_result, verifier_result) = tokio::try_join!(prover_task, verifier_task)?;

        let Ok(prover_result) = prover_result else {
            return Ok(TestOutput {
                passed: false,
                time: start.elapsed().as_secs(),
                timed_out: true,
            });
        };

        let Ok(verifier_result) = verifier_result else {
            return Ok(TestOutput {
                passed: false,
                time: start.elapsed().as_secs(),
                timed_out: true,
            });
        };

        Ok(TestOutput {
            passed: prover_result.is_ok() && verifier_result.is_ok(),
            time: start.elapsed().as_secs(),
            timed_out: false,
        })
    }

    pub async fn run_bench(&self, bench: &BenchConfig) -> Result<Metrics> {
        let State::Running = &self.state else {
            return Err(anyhow!("runner not started"));
        };

        let mut verifier_provider = VerifierProvider::new(DEFAULT_SERVER_IP).await?;
        let mut prover_provider = ProverProvider::new(
            (DEFAULT_SERVER_IP.to_string(), DEFAULT_SERVER_PORT),
            verifier_provider.addr(),
        );

        let prover_task = {
            let bench = bench.clone();
            tokio::spawn(async move { bench_prover(&mut prover_provider, &bench).await })
        };

        let verifier_task = {
            let bench = bench.clone();
            tokio::spawn(async move { bench_verifier(&mut verifier_provider, &bench).await })
        };

        let (metrics, _) = tokio::try_join!(prover_task, verifier_task)?;

        Ok(metrics?)
    }

    pub async fn stop(&mut self) -> Result<()> {
        match &mut self.state {
            State::Running => {}
            _ => {}
        }

        self.state = State::Done;

        Ok(())
    }
}

enum State {
    Init,
    Running,
    Done,
}
