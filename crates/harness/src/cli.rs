use clap::{Parser, Subcommand};

use crate::Target;

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand)]
pub enum Command {
    /// runs tests.
    Test {
        /// Target platform.
        #[arg(long, default_value = "native")]
        target: Option<Target>,
        /// Name prefix filter.
        #[arg(long)]
        name: Option<String>,
        /// Timeout in seconds.
        #[arg(long, default_value = "300")]
        timeout: Option<u64>,
    },
    /// runs benchmarks.
    Bench {
        /// Target platform.
        #[arg(short, long, default_value = "native")]
        target: Option<Target>,
        /// Configuration path.
        #[arg(short, long, default_value = "bench.toml")]
        config: Option<String>,
        /// Output file path.
        #[arg(short, long, default_value = "metrics.csv")]
        output: Option<String>,
    },
}
