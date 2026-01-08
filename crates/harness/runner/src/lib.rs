pub mod cli;
mod executor;
mod network;
pub(crate) mod rpc;
mod server_fixture;
pub mod wasm_server;
mod ws_proxy;

#[cfg(feature = "debug")]
mod debug_prelude;

use std::{collections::HashMap, time::Duration};

use anyhow::Result;
use clap::Parser;
use csv::WriterBuilder;
use harness_core::{
    ExecutorConfig, Id, IoMode, Role, TEST_APP_BANDWIDTH, TEST_APP_DELAY, TEST_PROTO_BANDWIDTH,
    TEST_PROTO_DELAY,
    bench::{BenchItems, BenchOutput, Measurement, WARM_UP_BENCH},
    network::NetworkConfig,
    rpc::{BenchCmd, TestCmd},
    test::TestStatus,
};
use indicatif::{ProgressBar, ProgressStyle};

use cli::{Cli, Command};
use executor::Executor;
use server_fixture::ServerFixture;

#[cfg(feature = "debug")]
use crate::debug_prelude::*;

use crate::{cli::Route, network::Network, wasm_server::WasmServer, ws_proxy::WsProxy};

/// Statistics for a benchmark configuration
#[derive(Debug, Clone)]
struct BenchStats {
    group: Option<String>,
    bandwidth: usize,
    latency: usize,
    upload_size: usize,
    download_size: usize,
    times: Vec<u64>,
}

impl BenchStats {
    fn median(&self) -> f64 {
        let mut sorted = self.times.clone();
        sorted.sort();
        let len = sorted.len();
        if len == 0 {
            return 0.0;
        }
        if len.is_multiple_of(2) {
            (sorted[len / 2 - 1] + sorted[len / 2]) as f64 / 2.0
        } else {
            sorted[len / 2] as f64
        }
    }
}

/// Print summary table of benchmark results
fn print_bench_summary(stats: &[BenchStats]) {
    if stats.is_empty() {
        println!("\nNo benchmark results to display (only warmup was run).");
        return;
    }

    println!("\n{}", "=".repeat(80));
    println!("TLSNotary Benchmark Results");
    println!("{}", "=".repeat(80));
    println!();

    for stat in stats {
        let group_name = stat.group.as_deref().unwrap_or("unnamed");
        println!(
            "{} ({} Mbps, {}ms latency, {}KB↑ {}KB↓):",
            group_name,
            stat.bandwidth,
            stat.latency,
            stat.upload_size / 1024,
            stat.download_size / 1024
        );
        println!("  Median:  {:.2}s", stat.median() / 1000.0);
        println!();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, Default)]
pub enum Target {
    #[default]
    Native,
    Browser,
}

struct Runner {
    network: Network,
    server_fixture: ServerFixture,
    wasm_server: WasmServer,
    proto_proxy: WsProxy,
    app_proxy: WsProxy,
    exec_p: Executor,
    exec_v: Executor,
    started: bool,
}

/// Collects display-related environment variables for headed browser mode.
/// Works with both X11 and Wayland by collecting whichever vars are present.
fn collect_display_env_vars() -> Vec<String> {
    const DISPLAY_VARS: &[&str] = &[
        "DISPLAY",         // X11
        "XAUTHORITY",      // X11 auth
        "WAYLAND_DISPLAY", // Wayland
        "XDG_RUNTIME_DIR", // Wayland runtime dir
    ];

    DISPLAY_VARS
        .iter()
        .filter_map(|&var| {
            std::env::var(var)
                .ok()
                .map(|val| format!("{}={}", var, val))
        })
        .collect()
}

impl Runner {
    fn new(cli: &Cli) -> Result<Self> {
        let Cli {
            target,
            subnet,
            headed,
            ..
        } = cli;
        let current_path = std::env::current_exe().unwrap();
        let fixture_path = current_path.parent().unwrap().join("server-fixture");
        let network_config = NetworkConfig::new(*subnet);
        let network = Network::new(network_config.clone())?;

        // Collect display env vars once if headed mode is enabled
        let display_env = if *headed {
            collect_display_env_vars()
        } else {
            Vec::new()
        };

        let server_fixture =
            ServerFixture::new(fixture_path, network.ns_app().clone(), network_config.app);
        let wasm_server = WasmServer::new(
            network.ns_0().clone(),
            current_path.parent().unwrap().join("wasm-server"),
            network_config.wasm,
        );
        let proto_proxy = WsProxy::new(network_config.proto_proxy);
        let app_proxy = WsProxy::new(network_config.app_proxy);
        let exec_p = Executor::new(
            network.ns_0().clone(),
            ExecutorConfig::builder()
                .id(Id::Zero)
                .io_mode(IoMode::Client)
                .network_config(network_config.clone())
                .build(),
            *target,
            display_env.clone(),
        );
        let exec_v = Executor::new(
            network.ns_1().clone(),
            ExecutorConfig::builder()
                .id(Id::One)
                .io_mode(IoMode::Server)
                .network_config(network_config.clone())
                .build(),
            Target::Native,
            Vec::new(), // Verifier doesn't need display env
        );

        Ok(Self {
            network,
            server_fixture,
            wasm_server,
            proto_proxy,
            app_proxy,
            exec_p,
            exec_v,
            started: false,
        })
    }

    async fn start_services(&mut self) -> Result<()> {
        if self.started {
            return Ok(());
        }

        self.server_fixture.start()?;
        self.wasm_server.start()?;
        self.proto_proxy.start().await?;
        self.app_proxy.start().await?;
        self.started = true;

        Ok(())
    }
}

pub async fn main() -> Result<()> {
    #[cfg(feature = "debug")]
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    // Validate --headed requires --target browser
    if cli.headed && cli.target != Target::Browser {
        anyhow::bail!("--headed can only be used with --target browser");
    }

    let mut runner = Runner::new(&cli)?;

    let mut exit_code = 0;
    match cli.command {
        Command::Test { list, .. } if list => {
            runner.start_services().await?;
            runner.exec_p.start().await?;
            let tests = runner.exec_p.get_tests().await?;
            for test in tests {
                println!("{test}");
            }
        }
        Command::Test { name, .. } => {
            runner.start_services().await?;
            runner.exec_p.start().await?;
            runner.exec_v.start().await?;

            let tests = runner.exec_p.get_tests().await?;
            // Filter tests by name if provided
            let tests = if let Some(name) = name {
                tests
                    .into_iter()
                    .filter(|t| t == &name || t.starts_with(&name))
                    .collect()
            } else {
                tests
            };

            runner
                .network
                .set_proto_config(TEST_PROTO_BANDWIDTH, TEST_PROTO_DELAY)?;
            runner
                .network
                .set_app_config(TEST_APP_BANDWIDTH, TEST_APP_DELAY)?;

            let mut success = 0;
            let mut failed = 0;
            let mut failed_tests = Vec::new();
            for name in tests {
                let (output_p, output_v) = tokio::try_join!(
                    runner.exec_p.test(TestCmd {
                        name: name.clone(),
                        role: Role::Prover,
                    }),
                    runner.exec_v.test(TestCmd {
                        name: name.clone(),
                        role: Role::Verifier,
                    })
                )?;

                if output_p.status.is_passed() && output_v.status.is_passed() {
                    success += 1;
                    println!("{name}: passed");
                } else {
                    failed += 1;
                    failed_tests.push(name.clone());
                    eprintln!("{name}: failed");

                    if let TestStatus::Failed { reason } = output_p.status {
                        eprintln!("{name} prover failed.");
                        if let Some(reason) = reason {
                            eprintln!("reason: {reason}");
                        }
                    }

                    if let TestStatus::Failed { reason } = output_v.status {
                        eprintln!("{name} verifier failed.");
                        if let Some(reason) = reason {
                            eprintln!("reason: {reason}");
                        }
                    }
                }
            }

            println!("summary: {success} passed, {failed} failed");

            if failed > 0 {
                exit_code = 1;
                println!("failed: {}", failed_tests.join(", "));
            }
        }
        Command::Bench {
            config,
            output,
            samples,
            samples_override,
            skip_warmup,
        } => {
            // Print configuration info
            println!("TLSNotary Benchmark Harness");
            println!("Running benchmarks from: {}", config.display());
            println!("Output will be written to: {}", output.display());
            println!();

            let items: BenchItems = toml::from_str(&std::fs::read_to_string(config)?)?;
            let output_file = std::fs::File::create(output)?;
            let mut writer = WriterBuilder::new().from_writer(output_file);

            let mut benches = Vec::new();
            if !skip_warmup {
                benches.extend(vec![WARM_UP_BENCH; 3]);
            }
            benches.extend(items.to_benches(samples, samples_override));

            runner.start_services().await?;
            runner.exec_p.start().await?;
            runner.exec_v.start().await?;

            // Create progress bar
            let pb = ProgressBar::new(benches.len() as u64);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} {msg}")
                    .expect("valid template")
                    .progress_chars("█▓▒░ "),
            );

            // Collect measurements for stats
            let mut measurements_by_config: HashMap<String, Vec<u64>> = HashMap::new();

            let warmup_count = if skip_warmup { 0 } else { 3 };

            for (idx, config) in benches.iter().enumerate() {
                let is_warmup = idx < warmup_count;

                let group_name = if is_warmup {
                    format!("Warmup {}/{}", idx + 1, warmup_count)
                } else {
                    config.group.as_deref().unwrap_or("unnamed").to_string()
                };

                pb.set_message(format!(
                    "{} ({} Mbps, {}ms)",
                    group_name, config.bandwidth, config.protocol_latency
                ));

                runner
                    .network
                    .set_proto_config(config.bandwidth, config.protocol_latency.div_ceil(2))?;
                runner
                    .network
                    .set_app_config(config.bandwidth, config.app_latency.div_ceil(2))?;

                // Wait for the network to stabilize
                tokio::time::sleep(Duration::from_millis(100)).await;

                #[cfg(feature = "debug")]
                debug!("Starting bench in group {:?}", config.group);

                let (output, _) = tokio::try_join!(
                    runner.exec_p.bench(BenchCmd {
                        config: config.clone(),
                        role: Role::Prover,
                    }),
                    runner.exec_v.bench(BenchCmd {
                        config: config.clone(),
                        role: Role::Verifier,
                    })
                )?;

                let BenchOutput::Prover { metrics } = output else {
                    panic!("expected prover output");
                };

                // Collect metrics for stats (skip warmup benches)
                if !is_warmup {
                    let config_key = format!(
                        "{:?}|{}|{}|{}|{}",
                        config.group,
                        config.bandwidth,
                        config.protocol_latency,
                        config.upload_size,
                        config.download_size
                    );
                    measurements_by_config
                        .entry(config_key)
                        .or_default()
                        .push(metrics.time_total);
                }

                let measurement = Measurement::new(config.clone(), metrics);

                writer.serialize(measurement)?;
                writer.flush()?;

                pb.inc(1);
            }

            pb.finish_with_message("Benchmarks complete");

            // Compute and print statistics
            let mut all_stats: Vec<BenchStats> = Vec::new();
            for (key, times) in measurements_by_config {
                // Parse back the config from the key
                let parts: Vec<&str> = key.split('|').collect();
                if parts.len() >= 5 {
                    let group = if parts[0] == "None" {
                        None
                    } else {
                        Some(
                            parts[0]
                                .trim_start_matches("Some(\"")
                                .trim_end_matches("\")")
                                .to_string(),
                        )
                    };
                    let bandwidth: usize = parts[1].parse().unwrap_or(0);
                    let latency: usize = parts[2].parse().unwrap_or(0);
                    let upload_size: usize = parts[3].parse().unwrap_or(0);
                    let download_size: usize = parts[4].parse().unwrap_or(0);

                    all_stats.push(BenchStats {
                        group,
                        bandwidth,
                        latency,
                        upload_size,
                        download_size,
                        times,
                    });
                }
            }

            // Sort stats by group name for consistent output
            all_stats.sort_by(|a, b| {
                a.group
                    .cmp(&b.group)
                    .then(a.latency.cmp(&b.latency))
                    .then(a.bandwidth.cmp(&b.bandwidth))
            });

            print_bench_summary(&all_stats);
        }
        Command::Serve {} => {
            runner.start_services().await?;
            tokio::signal::ctrl_c().await?;
        }
        Command::Setup {} => {
            runner.network.create()?;

            println!("network created");
            runner.network.print_network();
        }
        Command::Clean {} => {
            runner.network.delete()?;

            println!("network deleted");
        }
        Command::Info {} => {
            runner.network.print_network();
        }
        Command::SetNetwork {
            route,
            bandwidth,
            latency: delay,
        } => match route {
            Route::Protocol => runner
                .network
                .set_proto_config(bandwidth, delay.div_ceil(2))?,
            Route::App => runner
                .network
                .set_app_config(bandwidth, delay.div_ceil(2))?,
        },
    }

    // Shut down the executors before exiting.
    if tokio::time::timeout(Duration::from_secs(5), async move {
        _ = tokio::join!(runner.exec_p.shutdown(), runner.exec_v.shutdown());
    })
    .await
    .is_err()
    {
        eprintln!("executor shutdown timed out");
    }

    if exit_code != 0 {
        std::process::exit(exit_code);
    }

    Ok(())
}
