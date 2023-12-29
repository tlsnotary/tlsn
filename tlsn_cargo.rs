#!/usr/bin/env cargo +nightly -Zscript
```cargo
[package]
name = "TLSN_cargo"
version = "0.0.1"
edition = "2021"

[dependencies]
clap = { version = "4.2", features = ["derive"] }
strum = { version = "0.25", features = ["derive"] }
```

use std::process::{Command, Stdio};

// https://rust-lang.github.io/rfcs/3424-cargo-script.html
// https://rust-lang-nursery.github.io/rust-cookbook/os/external.html#continuously-process-child-process-outputs
// https://rust-lang-nursery.github.io/rust-cookbook/cli/arguments.html
// https://rust-lang-nursery.github.io/rust-cookbook/cli/arguments.html
use clap::{Parser, Subcommand};
use strum::EnumIter;
use strum::IntoEnumIterator;

#[derive(Parser, Debug)]
#[command(name = "tlsn cargo")]
#[command(author = "Hendrik Eeckhaut")]
#[command(version = "0.1")]
#[command(about = "run a cargo command against all TLSNotary crates", long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,

    /// Optional package name to ...
    name: Option<String>,
}

#[derive(Subcommand, Debug, PartialEq)]
enum Commands {
    /// build all packages
    Build,
    /// clean all packages
    Clean,
    /// test all packages
    Test,
    /// list all packages
    List,
    /// check formatting
    Format,
    /// check that benchmarks compile
    Bench,
    /// Run clippy
    Clippy,
}

#[derive(EnumIter, Debug, PartialEq)]
enum Packages {
    UIDMUX,
    CIPHER,
    UNIVERSALHASH,
    AEAD,
    KEYEXCHANGE,
    POINTADDITION,
    PRF,
    TLS,
    TLSN,
    INTEGRATIONTESTS,
    NOTARYSERVER,
}

impl Packages {
    fn path(&self) -> &str {
        match self {
            Packages::UIDMUX => "components/uid-mux",
            Packages::CIPHER => "components/cipher",
            Packages::UNIVERSALHASH => "components/universal-hash",
            Packages::AEAD => "components/aead",
            Packages::KEYEXCHANGE => "components/key-exchange",
            Packages::POINTADDITION => "components/point-addition",
            Packages::PRF => "components/prf",
            Packages::TLS => "components/tls",
            Packages::TLSN => "tlsn",
            Packages::INTEGRATIONTESTS => "components/integration-tests",
            Packages::NOTARYSERVER => "notary-server",
        }
    }

    fn is_release(&self) -> bool {
        match self {
            Packages::INTEGRATIONTESTS | Packages::NOTARYSERVER => true,
            _ => false,
        }
    }

    fn all_features(&self) -> bool {
        match self {
            Packages::TLSN => true,
            _ => false,
        }
    }
}

fn get_cargo_args<'a>(package: &Packages, command: &'a Commands) -> Vec<&'a str> {
    match command {
        Commands::Build => {
            let mut args = vec!["+stable", "build"];
            if package.is_release() {
                args.push("--release");
            }
            args
        }
        Commands::Clean => vec!["clean"],
        Commands::Bench => vec!["+stable", "bench", "--no-run"],
        Commands::Clippy => {
            vec![
                "+stable",
                "clippy",
                "--all-features",
                "--examples",
                "--",
                "--deny",
                "warnings",
            ]
        }
        Commands::Format => vec!["+nightly", "fmt", "--check", "--all"],
        Commands::Test => {
            let mut args = if package.is_release() {
                vec!["+stable", "test", "--release", "--tests"]
            } else {
                vec![
                    "+stable",
                    "test",
                    "--lib",
                    "--bins",
                    "--tests",
                    "--examples",
                    "--workspace",
                ]
            };
            if package.all_features() {
                args.push("--all-features");
            };
            args
        }
        Commands::List => unreachable!(),
    }
}

fn main() {
    let args = Args::parse();

    let packages: Vec<Packages> = if let Some(single_package) = args.name {
        let p: Vec<_> = Packages::iter()
            .filter(|p| p.path().to_string() == single_package)
            .collect();
        if p.is_empty() {
            panic!("Invalid package name ..."); // should be one of..
        }
        p
    } else {
        Packages::iter().collect()
    };

    if args.command == Commands::List {
        println!("TLSN packages:");
        println!(
            "{:?}",
            &packages.iter().map(|p| p.path()).collect::<Vec<&str>>()
        );
        return;
    };

    // https://rust-lang-nursery.github.io/rust-cookbook/os/external.html#continuously-process-child-process-outputs
    for package in packages {
        let cargo_args = get_cargo_args(&package, &args.command);
        println!("{}: Running `cargo {:?}`", &package.path(), &cargo_args);
        let stdout = Command::new("cargo")
            .current_dir(package.path())
            .args(&cargo_args)
            .stdout(Stdio::piped())
            .spawn()
            .expect("TODO")
            .wait_with_output();
        // dbg!(&stdout);
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
