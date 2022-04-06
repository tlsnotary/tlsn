use std::io::Result;
fn main() -> Result<()> {
    #[cfg(feature = "proto")]
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
