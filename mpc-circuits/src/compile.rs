use clap::Parser;
use mpc_core::circuit::Circuit;
use mpc_core::proto::circuits::Circuit as ProtoCircuit;
use prost::Message;
use rayon::prelude::*;
use regex::Regex;
use std::env;
use std::fs::{create_dir, read_dir, write};
use std::io::Result;

#[derive(Clone, Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Path to directory containing circuits
    #[clap(required = true, short)]
    i: String,
    /// Path to directory to save outputs
    #[clap(required = true, short)]
    o: String,
}

fn process_file(file: &String, out_dir: &String) -> Result<()> {
    let version = env::var("CARGO_PKG_VERSION").unwrap();
    let name_pattern = Regex::new(r"(\w+)\.txt").unwrap();
    if let Some(cap) = name_pattern.captures(file.as_str()) {
        let name = cap.get(1).unwrap().as_str();
        let circ = Circuit::parse(file.as_str(), name, version.as_str()).unwrap();
        let circ = ProtoCircuit::from(circ);
        write(format!("{}/{}.bin", out_dir, name), circ.encode_to_vec()).unwrap();
    }
    Ok(())
}

fn main() {
    let args = Args::parse();
    if let Err(_) = read_dir(args.o.as_str()) {
        create_dir(args.o.as_str()).expect("Output directory does not exist, failed to create");
    }
    let circuit_files = read_dir(args.i).unwrap();
    let circuit_files: Vec<String> = circuit_files
        .into_iter()
        .map(|file| {
            let file = file.unwrap();
            let file = file.path();
            String::from(file.to_str().unwrap())
        })
        .collect();

    let _: Vec<Result<()>> = circuit_files
        .par_iter()
        .map(|file| process_file(file, &args.o))
        .collect();
}
