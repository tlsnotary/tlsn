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

#[cfg(feature = "debug")]
use crate::debug_prelude::*;

pub struct Executor {
    ns: Namespace,
    config: ExecutorConfig,
    target: Target,
    /// Display environment variables for headed mode (X11/Wayland).
    /// Empty means headless mode.
    display_env: Vec<String>,
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
    pub fn new(
        ns: Namespace,
        config: ExecutorConfig,
        target: Target,
        display_env: Vec<String>,
    ) -> Self {
        Self {
            ns,
            config,
            target,
            display_env,
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

                let mut args = vec![
                    "ip".into(),
                    "netns".into(),
                    "exec".into(),
                    self.ns.name().into(),
                    "env".into(),
                    format!("CONFIG={}", serde_json::to_string(&self.config)?),
                ];

                if cfg!(feature = "debug") {
                    let level = &std::env::var("RUST_LOG").unwrap_or("debug".to_string());
                    args.push("env".into());
                    args.push(format!("RUST_LOG={}", level));
                };

                args.push(executor_path.to_str().expect("valid path").into());

                let process = duct::cmd("sudo", args);

                let process = if !cfg!(feature = "debug") {
                    process
                        .stdout_capture()
                        .stderr_capture()
                        .unchecked()
                        .start()?
                } else {
                    process.unchecked().start()?
                };

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
                let (wasm_addr, wasm_port) = self.config.network().wasm;

                // Create a temporary directory for the browser profile.
                let tmp = duct::cmd!("mktemp", "-d").read()?;
                let tmp = tmp.trim();

                let headed = !self.display_env.is_empty();

                // Build command args based on headed/headless mode
                let mut args: Vec<String> = vec![
                    "ip".into(),
                    "netns".into(),
                    "exec".into(),
                    self.ns.name().into(),
                ];

                if headed {
                    // For headed mode: drop back to the current user and pass display env vars
                    // This allows the browser to connect to X11/Wayland while in the namespace
                    let user =
                        std::env::var("USER").context("USER environment variable not set")?;
                    args.extend(["sudo".into(), "-E".into(), "-u".into(), user, "env".into()]);
                    args.extend(self.display_env.clone());
                }

                args.push(chrome_path.to_string_lossy().into());
                args.push(format!("--remote-debugging-port={PORT_BROWSER}"));

                if headed {
                    // Headed mode: no headless, add flags to suppress first-run dialogs
                    args.extend(["--no-first-run".into(), "--no-default-browser-check".into()]);
                } else {
                    // Headless mode: original flags
                    args.extend([
                        "--headless".into(),
                        "--disable-dev-shm-usage".into(),
                        "--disable-gpu".into(),
                        "--disable-cache".into(),
                        "--disable-application-cache".into(),
                    ]);
                }

                args.extend([
                    "--no-sandbox".into(),
                    format!("--user-data-dir={tmp}"),
                    "--allowed-ips=10.250.0.1".into(),
                ]);

                let process = duct::cmd("sudo", &args);

                let process = if !cfg!(feature = "debug") {
                    process.stderr_capture().stdout_capture().start()?
                } else {
                    process.start()?
                };

                const TIMEOUT: usize = 10000;
                const DELAY: usize = 100;
                let mut retries = 0;
                let config = HandlerConfig {
                    // Bump the timeout for long-running benches.
                    request_timeout: Duration::from_secs(120),
                    ..Default::default()
                };

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
                            eprintln!("chromium error: {e:?}");
                        }
                    }
                });

                let page = browser
                    .new_page(&format!("http://{wasm_addr}:{wasm_port}/index.html"))
                    .await?;

                #[cfg(feature = "debug")]
                tokio::spawn(register_listeners(page.clone()).await?);

                #[cfg(feature = "debug")]
                async fn register_listeners(page: Page) -> Result<impl Future<Output = ()>> {
                    let mut logs = page.event_listener::<EventEntryAdded>().await?.fuse();
                    let mut exceptions =
                        page.event_listener::<EventExceptionThrown>().await?.fuse();

                    Ok(futures::future::join(
                        async move {
                            while let Some(event) = logs.next().await {
                                let entry = &event.entry;
                                match entry.level {
                                    LogEntryLevel::Error => {
                                        error!("{:?}", entry);
                                    }
                                    _ => {
                                        debug!("{:?}: {}", entry.timestamp, entry.text);
                                    }
                                }
                            }
                        },
                        async move {
                            while let Some(event) = exceptions.next().await {
                                error!("{:?}", event);
                            }
                        },
                    )
                    .map(|_| ()))
                }

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
}

impl Drop for Executor {
    fn drop(&mut self) {
        let State::Started { process, .. } = &mut self.state else {
            return;
        };

        _ = process.kill();
    }
}
