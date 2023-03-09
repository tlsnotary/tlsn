use hmac_sha256_circuits::{master_secret, premaster_secret, session_keys, verify_data};
use mpc_circuits::{proto, Circuit};
use prost::Message;
use rayon::prelude::*;
use std::{env, fs, io, path::Path, sync::Arc};

type CircuitBuilderMap = [(&'static str, fn() -> Arc<Circuit>)];

static CIRCUITS: &CircuitBuilderMap = &[
    ("premaster_secret", premaster_secret),
    ("master_secret", master_secret),
    ("session_keys", session_keys),
    ("cf_verify_data", || verify_data(b"client finished")),
    ("sf_verify_data", || verify_data(b"server finished")),
];

fn build_circuit<F>(name: &str, f: F) -> io::Result<()>
where
    F: FnOnce() -> Arc<Circuit>,
{
    let circ = f();
    let bytes = proto::Circuit::from(circ.as_ref()).encode_to_vec();
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
            let built = Path::new(&format!("circuits/bin/{}.bin", name)).is_file();
            !built || force_build
        })
        .map(|(name, f)| build_circuit(name, f))
        .collect::<io::Result<_>>()
}

fn main() -> io::Result<()> {
    build_circuits()?;
    Ok(())
}
