mod abi;

pub mod prover;
pub mod verifier;

pub use tlsn_core::{config, connection, webpki};

#[unsafe(no_mangle)]
unsafe extern "Rust" fn __getrandom_v03_custom(
    dest: *mut u8,
    len: usize,
) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}

fn always_fail(buf: &mut [u8]) -> Result<(), getrandom02::Error> {
    let code = core::num::NonZeroU32::new(1).unwrap();
    Err(getrandom02::Error::from(code))
}

getrandom02::register_custom_getrandom!(always_fail);
