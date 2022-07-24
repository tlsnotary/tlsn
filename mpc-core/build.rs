use std::io::Result;
fn main() -> Result<()> {
    #[cfg(feature = "proto")]
    prost_build::compile_protos(
        &[
            "proto/core.proto",
            "proto/ot.proto",
            "proto/garble.proto",
            "proto/point_addition.proto",
        ],
        &["proto/"],
    )?;
    Ok(())
}
