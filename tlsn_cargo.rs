#!/usr/bin/env cargo +nightly -Zscript

//! ```cargo
//! [package]
//! name = "TLSN_cargo"
//! version = "0.0.1"
//! edition = "2021"
//!
//! [dependencies]
//! clap = { version = "4.2", features = ["derive"] }
//! ```

use std::process::{Command, Stdio};

// https://rust-lang.github.io/rfcs/3424-cargo-script.html
// https://rust-lang-nursery.github.io/rust-cookbook/os/external.html#continuously-process-child-process-outputs
// https://rust-lang-nursery.github.io/rust-cookbook/cli/arguments.html
// https://rust-lang-nursery.github.io/rust-cookbook/cli/arguments.html
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "tlsn cargo")]
#[command(author = "Hendrik Eeckhaut")]
#[command(version = "0.1")]
#[command(about = "run a cargo command against all TLSNotary crates", long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// build all packages
    Build,
    /// clean all packages
    Clean,
    /// test all packages
    Test,
    /// list all packages
    List,
    /// check formatting in all packages
    Format,
    /// Run clippy for all packages
    Clippy, // {
            //     /// extra arguments
            //     #[arg(short, long, default_value = "--all-features -- -D warnings")]
            //     extra_args: Option<String>,
            // },
}

const TLSN_PACKAGES: &[&str] = &[
    "components/uid-mux",
    "components/cipher",
    "components/universal-hash",
    "components/aead",
    "components/key-exchange",
    "components/point-addition",
    "components/prf",
    "components/tls",
    "tlsn",
    "components/integration-tests",
    "notary-server",
];

fn main() {
    let args = Args::parse();

    let cargo_args = match args.command {
        Commands::Build => vec!["build"],
        Commands::Clean => vec!["clean"],
        Commands::Clippy => {
            vec![
                "clippy",
                "--all-features",
                "--examples",
                "--",
                "-D",
                "warnings",
            ]
        }
        Commands::Format => vec!["+nightly", "fmt", "--check", "--all"],
        Commands::List => {
            println!("TLSN packages:");
            println!("{:?}", TLSN_PACKAGES);
            return;
        }
        Commands::Test => vec![
            "test",
            "--lib",
            "--bins",
            "--tests",
            "--examples",
            "--workspace",
        ],
    };

    // let f: Vec<_> = extra_args.split(' ').collect();
    // let binding = [command];
    // let args: Vec<_> = binding.iter().chain(f.iter()).collect();

    // https://rust-lang-nursery.github.io/rust-cookbook/os/external.html#continuously-process-child-process-outputs
    for name in TLSN_PACKAGES.into_iter() {
        println!("{}: Running `Cargo {:?}`", name, &cargo_args);
        let stdout = Command::new("cargo")
            .current_dir(name)
            .args(&cargo_args)
            .stdout(Stdio::piped())
            .spawn()
            .expect("TODO")
            .wait_with_output();
        if let Ok(output) = stdout {
            if !output.status.success() {
                if !output.stderr.is_empty() {
                    let stderr_string =
                        String::from_utf8(output.stderr).expect("Our bytes should be valid utf8");
                    println!("{stderr_string}");
                }
                if !output.stdout.is_empty() {
                    let stdout_string =
                        String::from_utf8(output.stdout).expect("Our bytes should be valid utf8");
                    println!("{stdout_string}");
                }

                break;
            }
        } else {
            //Err
            break;
        }
    }
}
