use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use ipnet::Ipv4Net;

use crate::Target;

#[derive(Parser)]
#[command(version, about, name = "tlsn-harness-runner", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
    /// Target platform.
    #[arg(long, default_value = "native")]
    pub target: Target,
    /// Subnet to assign harness network interfaces.
    #[arg(long, default_value = "10.250.0.0/24", env = "SUBNET")]
    pub subnet: Ipv4Net,
}

#[derive(Subcommand)]
pub enum Command {
    /// runs tests.
    Test {
        /// Name prefix filter.
        #[arg(long)]
        name: Option<String>,
        /// List tests.
        #[arg(long, exclusive = true)]
        list: bool,
    },
    /// runs benchmarks.
    Bench {
        /// Configuration path.
        #[arg(short, long, default_value = "bench.toml")]
        config: PathBuf,
        /// Output file path.
        #[arg(short, long, default_value = "metrics.csv")]
        output: PathBuf,
        /// Number of samples to measure per benchmark. This is overridden by
        /// the number of samples specified in the configuration
        /// file unless `samples_override` is set.
        #[arg(short, long, default_value = "10")]
        samples: usize,
        /// Override the number of samples specified in the configuration file.
        #[arg(long)]
        samples_override: bool,
        /// Skip warmup.
        #[arg(long)]
        skip_warmup: bool,
    },
    /// serves runner utilities such as the application server fixture, WASM
    /// server and WS proxy.
    Serve {},
    /// sets up the harness network.
    Setup {},
    /// cleans up the harness network.
    Clean {},
    /// prints the harness network configuration.
    Info {},
    /// sets the connection configuration.
    SetNetwork {
        /// The route to set.
        route: Route,
        /// The bandwidth to set.
        bandwidth: usize,
        /// The latency to set.
        latency: usize,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Route {
    Protocol,
    App,
}
