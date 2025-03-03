use std::{fs::metadata, io::Write};

use anyhow::{Context, Result};
use clap::Parser;
use csv::WriterBuilder;
use tlsn_harness::{
    bench::{Config, Measurement},
    cli::{Cli, Command},
    runner::Runner,
    test::{collect_tests, TestConfig, DEFAULT_TEST_TIMEOUT},
    Target,
};
use tracing::debug;
use tracing_subscriber::EnvFilter;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let Cli { command } = tlsn_harness::cli::Cli::parse();

    let Some(command) = command else {
        return Err(anyhow::anyhow!("No command provided"));
    };

    match command {
        Command::Test {
            target,
            name,
            timeout,
        } => {
            let mut runner = match target.unwrap_or_default() {
                Target::Native => Runner::new_native(),
                Target::Browser => Runner::new_browser(),
            };

            runner.start().await?;
            debug!("runner started");

            let mut passed = 0;
            let mut failed = 0;
            // TODO: Run in parallel.
            for name in collect_tests(name.as_deref()) {
                println!("running test: '{}'", name);
                let output = runner
                    .run_test(&TestConfig {
                        name: name.to_string(),
                        timeout: timeout.unwrap_or(DEFAULT_TEST_TIMEOUT),
                    })
                    .await?;

                if !output.passed {
                    eprintln!(
                        "test failed: '{}' time={}, time_out={}",
                        name, output.time, output.timed_out
                    );
                    failed += 1;
                } else {
                    passed += 1;
                }
            }

            println!("passed: {}, failed: {}", passed, failed);

            runner.stop().await?;

            if failed > 0 {
                std::process::exit(1);
            }
        }
        Command::Bench {
            target,
            config,
            output,
        } => {
            let config_path = config.unwrap_or_else(|| "bench.toml".to_string());
            let config: Config = toml::from_str(
                &std::fs::read_to_string(config_path).context("failed to read config file")?,
            )
            .context("failed to parse config")?;

            let output_path = output.unwrap_or_else(|| "metrics.csv".to_string());
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&output_path)
                .context("failed to open metrics file")?;
            let mut writer = WriterBuilder::new()
                // If file is not empty, assume that the CSV header is already present in the file.
                .has_headers(metadata(output_path)?.len() == 0)
                .from_writer(&mut file);

            let mut runner = match target.unwrap_or_default() {
                Target::Native => Runner::new_native(),
                Target::Browser => Runner::new_browser(),
            };

            runner.start().await?;
            debug!("runner started");

            for group in config.benches {
                let instances = group.flatten();
                for config in instances {
                    let metrics = runner.run_bench(&config).await?;

                    writer.serialize(Measurement::new(config, metrics))?;
                    writer.flush()?;
                }
            }
            drop(writer);
            file.flush()?;

            runner.stop().await?;
        }
    }

    Ok(())
}
