use std::io::Result;
fn main() -> Result<()> {
    prost_build::compile_protos(&["src/core.proto", "src/ot.proto"], &["src/"])?;
    Ok(())
}
