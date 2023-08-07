/// The single place where we generate random material
/// for our own use.  These functions never fail,
/// they panic on error.
use rand::{rngs::OsRng, Rng};
use tls_core::msgs::codec;

/// Fill the whole slice with random material.
pub(crate) fn fill_random(bytes: &mut [u8]) -> Result<(), GetRandomFailed> {
    OsRng.fill(bytes);
    Ok(())
}

/// Make a Vec<u8> of the given size
/// containing random material.
pub(crate) fn random_vec(len: usize) -> Result<Vec<u8>, GetRandomFailed> {
    let mut v = vec![0; len];
    fill_random(&mut v)?;
    Ok(v)
}

/// Return a uniformly random u32.
pub(crate) fn random_u32() -> Result<u32, GetRandomFailed> {
    let mut buf = [0u8; 4];
    fill_random(&mut buf)?;
    codec::decode_u32(&buf).ok_or(GetRandomFailed)
}

#[derive(Debug)]
pub struct GetRandomFailed;
