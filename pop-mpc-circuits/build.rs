use pop_mpc_core::circuit::Circuit;
use pop_mpc_core::proto::circuits::Circuit as ProtoCircuit;
use prost::Message;
use regex::Regex;
use std::env;
use std::fs::{read_dir, write};
use std::io::Result;

fn main() -> Result<()> {
    let name_pattern = Regex::new(r"circuits/(\w+)\.txt").unwrap();
    let circuit_files = read_dir("circuits/").unwrap();
    let version = env::var("CARGO_PKG_VERSION").unwrap();
    let out_dir = "./compiled/".to_string();

    for circuit_file in circuit_files {
        let circuit_file = circuit_file.unwrap();
        let path = circuit_file.path();
        let path = path.to_str().unwrap();
        if let Some(cap) = name_pattern.captures(path) {
            let name = cap.get(1).unwrap().as_str();
            let circ = Circuit::parse(path, name, version.as_str()).unwrap();
            let circ = ProtoCircuit::from(circ);
            write(format!("{}/{}.bin", out_dir, name), circ.encode_to_vec()).unwrap();
        } else {
            continue;
        }
    }
    Ok(())
}
