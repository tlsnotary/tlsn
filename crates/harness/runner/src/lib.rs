pub mod cli;
mod executor;
mod network;
pub(crate) mod rpc;
mod server_fixture;
pub mod wasm_server;
mod ws_proxy;

use std::time::Duration;

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

use cli::{Cli, Command};
use executor::Executor;
use server_fixture::ServerFixture;

use crate::{cli::Route, network::Network, wasm_server::WasmServer, ws_proxy::WsProxy};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Target {
    Native,
    Browser,
}

impl Default for Target {
    fn default() -> Self {
        Self::Native
    }
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

impl Runner {
    fn new(cli: &Cli) -> Result<Self> {
        let Cli { target, subnet, .. } = cli;
        let current_path = std::env::current_exe().unwrap();
        let fixture_path = current_path.parent().unwrap().join("server-fixture");
        let network_config = NetworkConfig::new(*subnet);
        let network = Network::new(network_config.clone())?;

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
        );
        let exec_v = Executor::new(
            network.ns_1().clone(),
            ExecutorConfig::builder()
                .id(Id::One)
                .io_mode(IoMode::Server)
                .network_config(network_config.clone())
                .build(),
            Target::Native,
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
    let cli = Cli::parse();
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

            for config in benches {
                runner
                    .network
                    .set_proto_config(config.bandwidth, config.protocol_latency.div_ceil(2))?;
                runner
                    .network
                    .set_app_config(config.bandwidth, config.app_latency.div_ceil(2))?;

                // Wait for the network to stabilize
                tokio::time::sleep(Duration::from_millis(100)).await;

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

                let measurement = Measurement::new(config, metrics);

                writer.serialize(measurement)?;
                writer.flush()?;
            }
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

    runner.exec_p.shutdown().await?;
    runner.exec_v.shutdown().await?;

    if exit_code != 0 {
        std::process::exit(exit_code);
    }

    Ok(())
}
