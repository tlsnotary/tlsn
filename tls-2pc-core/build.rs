use mpc_circuits::{proto, Circuit};
use prost::Message;
use rayon::prelude::*;
use std::{env, fs, io, path::Path};
use tls_circuits::{c1, c2, c3, c4, c5, c6, c7};

static CIRCUITS: &[(&str, fn() -> Circuit)] = &[
    ("c1", c1),
    ("c2", c2),
    ("c3", c3),
    ("c4", c4),
    ("c5", c5),
    ("c6", c6),
    ("c7", c7),
];

fn build_circuit<F>(name: &str, f: F) -> io::Result<()>
where
    F: FnOnce() -> Circuit,
{
    let circ = f();
    let bytes = proto::Circuit::from(circ).encode_to_vec();
    fs::write(format!("circuits/bin/{}.bin", name), bytes)
}

fn build_circuits() -> io::Result<()> {
    let bin_dir = Path::new("circuits/bin/").to_owned();
    if !bin_dir.is_dir() {
        fs::create_dir(bin_dir)?;
    }
    println!("cargo:rerun-if-changed=circuits/bin");
    let force_build = env::var("CARGO_FEATURE_BUILD_CIRCUITS").is_ok();
    CIRCUITS
        .into_par_iter()
        .filter(|(name, _)| {
            let enabled = env::var(format!("CARGO_FEATURE_{}", name.to_ascii_uppercase())).is_ok();
            let built = Path::new(&format!("circuits/bin/{}.bin", name)).is_file();
            enabled && (!built || force_build)
        })
        .map(|(name, f)| build_circuit(name, f))
        .collect::<io::Result<_>>()
}

fn main() -> io::Result<()> {
    build_circuits()?;
    Ok(())
}
