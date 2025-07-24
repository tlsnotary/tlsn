use std::time::Duration;

use anyhow::{Context, Result, anyhow};

use chromiumoxide::{
    Browser,
    cdp::browser_protocol::{
        network::{EnableParams, SetCacheDisabledParams},
        page::ReloadParams,
    },
    handler::HandlerConfig,
};
use futures::StreamExt;
use harness_core::{
    ExecutorConfig, Id,
    bench::BenchOutput,
    network::PORT_BROWSER,
    rpc::{BenchCmd, TestCmd},
    test::{TestOutput, TestStatus},
};

use crate::{Target, network::Namespace, rpc::Rpc};

pub struct Executor {
    ns: Namespace,
    config: ExecutorConfig,
    target: Target,
    state: State,
}

#[allow(clippy::large_enum_variant)]
enum State {
    Init,
    Started {
        process: duct::Handle,
        rpc: Rpc,
        browser: Option<Browser>,
    },
    Stopped,
}

impl State {
    fn take(&mut self) -> Self {
        std::mem::replace(self, State::Stopped)
    }
}

impl Executor {
    pub fn new(ns: Namespace, config: ExecutorConfig, target: Target) -> Self {
        Self {
            ns,
            config,
            target,
            state: State::Init,
        }
    }

    pub async fn start(&mut self) -> Result<()> {
        match self.target {
            Target::Native => {
                let current_path = std::env::current_exe().unwrap();
                let executor_path = current_path.parent().unwrap().join("executor-native");

                let rpc_addr = match self.config.id() {
                    Id::Zero => self.config.network().rpc_0,
                    Id::One => self.config.network().rpc_1,
                };

                let process = duct::cmd!(
                    "sudo",
                    "ip",
                    "netns",
                    "exec",
                    self.ns.name(),
                    "env",
                    format!("CONFIG={}", serde_json::to_string(&self.config)?),
                    executor_path,
                )
                .stdout_capture()
                .stderr_capture()
                .unchecked()
                .start()?;

                let rpc = Rpc::new_native(rpc_addr).await?;

                self.state = State::Started {
                    process,
                    rpc,
                    browser: None,
                };
            }
            Target::Browser => {
                let chrome_path = chromiumoxide::detection::default_executable(Default::default())
                    .map_err(|_| anyhow!("failed to detect chrome path"))?;

                let rpc_addr = match self.config.id() {
                    Id::Zero => self.config.network().rpc_0,
                    Id::One => self.config.network().rpc_1,
                };

                // Create a temporary directory for the browser profile.
                let tmp = duct::cmd!("mktemp", "-d").read()?;
                let tmp = tmp.trim();

                let process = duct::cmd!(
                    "sudo",
                    "ip",
                    "netns",
                    "exec",
                    self.ns.name(),
                    chrome_path,
                    format!("--remote-debugging-port={PORT_BROWSER}"),
                    "--headless",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--disable-cache",
                    "--disable-application-cache",
                    "--no-sandbox",
                    format!("--user-data-dir={tmp}"),
                    format!("--allowed-ips=10.250.0.1"),
                )
                .stderr_capture()
                .stdout_capture()
                .start()?;

                const TIMEOUT: usize = 10000;
                const DELAY: usize = 100;
                let mut retries = 0;
                let mut config = HandlerConfig::default();
                // Bump the timeout for long-running benches.
                config.request_timeout = Duration::from_secs(120);

                let (browser, mut handler) = loop {
                    match Browser::connect_with_config(
                        format!("http://{}:{}", rpc_addr.0, PORT_BROWSER),
                        config.clone(),
                    )
                    .await
                    {
                        Ok(browser) => break browser,
                        Err(e) => {
                            retries += 1;
                            if retries * DELAY > TIMEOUT {
                                return Err(e.into());
                            }
                            tokio::time::sleep(Duration::from_millis(DELAY as u64)).await;
                        }
                    }
                };

                tokio::spawn(async move {
                    while let Some(res) = handler.next().await {
                        if let Err(e) = res {
                            if e.to_string()
                                == "data did not match any variant of untagged enum Message"
                            {
                                // Do not log this error. It appears to be
                                // caused by a bug upstream.
                                // https://github.com/mattsse/chromiumoxide/issues/167
                                continue;
                            }
                            eprintln!("chromium error: {:?}", e);
                        }
                    }
                });

                let rpc = self.new_browser_rpc(&browser).await?;

                self.state = State::Started {
                    process,
                    rpc,
                    browser: Some(browser),
                };
            }
        }

        Ok(())
    }

    pub async fn get_tests(&mut self) -> Result<Vec<String>> {
        let State::Started { rpc, .. } = &mut self.state else {
            return Err(anyhow!("executor not started"));
        };

        rpc.get_tests().await?.map_err(From::from)
    }

    pub async fn test(&mut self, test: TestCmd) -> Result<TestOutput> {
        let State::Started { process, rpc, .. } = &mut self.state else {
            return Err(anyhow!("executor not started"));
        };

        let output: Result<TestOutput> = match rpc.test(test).await {
            Ok(res) => res.map_err(From::from),
            // Test could cause the native executor process to panic.
            Err(e) if self.target == Target::Native => {
                // Wait a moment to give the process time to exit.
                tokio::time::sleep(Duration::from_millis(100)).await;

                if let Some(output) = process.try_wait()? {
                    let res = if output.status.success() {
                        Err(e).context("executor process closed with success exit code even though RPC call returned an error")
                    } else {
                        Ok(TestOutput {
                            status: TestStatus::Failed {
                                reason: Some(String::from_utf8_lossy(&output.stderr).to_string()),
                            },
                        })
                    };

                    // Restart the executor.
                    self.start().await?;

                    return res;
                }

                return Err(e.into());
            }
            Err(e) => {
                return Err(e.into());
            }
        };

        output
    }

    pub async fn bench(&mut self, bench: BenchCmd) -> Result<BenchOutput> {
        let State::Started { rpc, .. } = &mut self.state else {
            return Err(anyhow!("executor not started"));
        };

        rpc.bench(bench).await?.map_err(From::from)
    }

    pub fn shutdown(&mut self) -> impl Future<Output = Result<()>> {
        let state = self.state.take();

        async move {
            let State::Started {
                process, browser, ..
            } = state
            else {
                return Ok(());
            };

            if let Some(mut browser) = browser {
                browser.close().await?;
            };

            tokio::task::spawn_blocking(move || {
                _ = process.kill();
                _ = process.wait();
            })
            .await?;

            Ok(())
        }
    }

    /// Reloads the RPC server associated with this browser executor.
    pub async fn reload_browser_rpc(&mut self) -> Result<()> {
        if !self.is_browser() {
            return Err(anyhow!("executor target is not browser"));
        }
        let State::Started {
            process,
            rpc,
            browser,
        } = self.state.take()
        else {
            return Err(anyhow!("executor is not in the started state"));
        };

        rpc.shutdown().await?;

        let browser = browser.expect("browser is set for browser target");

        let rpc = self.new_browser_rpc(&browser).await?;

        self.state = State::Started {
            process,
            rpc,
            browser: Some(browser),
        };

        Ok(())
    }

    /// Creates a new RPC server for this browser executor.
    async fn new_browser_rpc(&self, browser: &Browser) -> Result<Rpc> {
        if !self.is_browser() {
            return Err(anyhow!("executor target is not browser"));
        }

        let (wasm_addr, wasm_port) = self.config.network().wasm;

        let page = browser
            .new_page(&format!("http://{}:{}/index.html", wasm_addr, wasm_port))
            .await?;

        page.execute(EnableParams::builder().build()).await?;
        page.execute(SetCacheDisabledParams {
            cache_disabled: true,
        })
        .await?;
        page.execute(ReloadParams::builder().ignore_cache(true).build())
            .await?;
        page.wait_for_navigation().await?;
        page.bring_to_front().await?;
        page.evaluate(format!(
            r#"
                        (async () => {{
                            const config = JSON.parse('{config}');
                            console.log("initializing executor", config);
                            await window.executor.init(config);
                            console.log("executor initialized");
                            return;
                        }})();
                    "#,
            config = serde_json::to_string(&self.config)?
        ))
        .await?;

        let rpc = Rpc::new_browser(page);

        Ok(rpc)
    }

    pub fn is_browser(&self) -> bool {
        self.target == Target::Browser
    }
}

impl Drop for Executor {
    fn drop(&mut self) {
        let State::Started { process, .. } = &mut self.state else {
            return;
        };

        _ = process.kill();
    }
}
