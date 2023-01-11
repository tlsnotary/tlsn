// Parses Bristol-fashion circuit and saves it in yaml format

use clap::Parser;
use mpc_circuits::{Circuit, CircuitSpec};
use regex::Regex;
use serde_yaml::to_string;
use std::fs::{create_dir, read_dir, write};

#[derive(Clone, Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Path to bristol fashion circuit
    #[clap(short)]
    i: String,
    /// Path to directory to save output
    #[clap(short, default_value = "circuits/specs")]
    o: String,
}

fn main() {
    let args = Args::parse();
    if let Err(_) = read_dir(args.o.as_str()) {
        create_dir(args.o.as_str()).expect("Output directory does not exist, failed to create");
    }
    let path = args.i.as_str();

    let name_pattern = Regex::new(r"(\w+)\.txt").unwrap();
    if let Some(cap) = name_pattern.captures(path) {
        let name = cap.get(1).unwrap().as_str();
        let circ = Circuit::parse(path, name, "").expect("Failed to parse");
        let circ = CircuitSpec::from(circ.as_ref());
        write(
            format!("{}/{}.yml", args.o.as_str(), name),
            to_string(&circ).expect("Failed to serialize yaml"),
        )
        .expect("Failed to write file");
    } else {
        panic!("Must provide .txt file")
    }
    println!("Successfully saved file to {}", args.o.as_str());
}
