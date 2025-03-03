mod browser;
mod native;
pub(crate) mod server_fixture;
pub(crate) mod tlsn_fixture;

use anyhow::Result;

use crate::{
    bench::{BenchConfig, Metrics},
    test::{TestConfig, TestOutput},
};

pub struct Runner {
    inner: Inner,
}

impl Runner {
    pub fn new_native() -> Self {
        Self {
            inner: Inner::Native(native::NativeRunner::new()),
        }
    }

    pub fn new_browser() -> Self {
        Self {
            inner: Inner::Browser(browser::BrowserRunner::new()),
        }
    }

    pub async fn start(&mut self) -> Result<()> {
        match &mut self.inner {
            Inner::Native(runner) => runner.start().await,
            Inner::Browser(runner) => runner.start().await,
        }
    }

    pub async fn run_test(&self, test: &TestConfig) -> Result<TestOutput> {
        match &self.inner {
            Inner::Native(runner) => runner.run_test(test).await,
            Inner::Browser(runner) => runner.run_test(test).await,
        }
    }

    pub async fn run_bench(&self, bench: &BenchConfig) -> Result<Metrics> {
        match &self.inner {
            Inner::Native(runner) => runner.run_bench(bench).await,
            Inner::Browser(runner) => runner.run_bench(bench).await,
        }
    }

    pub async fn stop(&mut self) -> Result<()> {
        match &mut self.inner {
            Inner::Native(runner) => runner.stop().await,
            Inner::Browser(runner) => runner.stop().await,
        }
    }
}

enum Inner {
    Native(native::NativeRunner),
    Browser(browser::BrowserRunner),
}
