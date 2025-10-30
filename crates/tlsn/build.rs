fn main() {
    println!("cargo:rustc-check-cfg=cfg(tlsn_insecure)");
}
