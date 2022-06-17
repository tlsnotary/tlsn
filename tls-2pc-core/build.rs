use std::io::Result;
fn main() -> Result<()> {
    #[cfg(feature = "proto")]
    prost_build::compile_protos(&["proto/handshake.proto"], &["proto/"])?;
    Ok(())
}
