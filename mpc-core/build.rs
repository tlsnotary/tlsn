use std::io::Result;
fn main() -> Result<()> {
    prost_build::compile_protos(
        &[
            "proto/core.proto",
            "proto/ot.proto",
            "proto/garble.proto",
            "proto/circuits.proto",
            "proto/secret_share.proto",
        ],
        &["proto/"],
    )?;
    Ok(())
}
