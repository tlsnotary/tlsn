use mpc_circuits::{proto::Circuit as ProtoCircuit, CircuitSpec};
use prost::Message;
use regex::Regex;
use std::{fs, io, path::Path};

#[allow(dead_code)]
fn build_specs() -> Result<(), io::Error> {
    let re = Regex::new(r"(\w+)\.yml").unwrap();
    let spec_files = fs::read_dir("circuits/specs")?;
    for file in spec_files {
        let file = file.expect("failed to read file");
        let filename = file
            .file_name()
            .into_string()
            .expect("couldn't convert filename to string");
        if let Some(captures) = re.captures(&filename) {
            let circ_name = captures.get(1).unwrap().as_str();
            if !Path::new(format!("circuits/bin/{}.bin", circ_name).as_str()).exists() {
                let bytes = std::fs::read(file.path())
                    .expect(format!("Failed to read file: {:?}", file.path()).as_str());
                let circ = CircuitSpec::from_yaml(&bytes)
                    .expect(format!("bad circuit spec {}", filename).as_str())
                    .build()
                    .expect(format!("bad circuit spec {}", filename).as_str());
                let proto = ProtoCircuit::from(circ);
                fs::write(
                    format!("circuits/bin/{}.bin", circ_name),
                    proto.encode_to_vec(),
                )
                .expect("failed to write circuit to disk");
            }
        }
    }

    Ok(())
}

fn main() -> io::Result<()> {
    //build_specs()?;
    Ok(())
}
