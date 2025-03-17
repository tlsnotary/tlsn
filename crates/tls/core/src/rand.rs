use crate::{msgs::codec, Error};
use rand::{rng, Rng};

/// Fill the whole slice with random material.
pub fn fill_random(bytes: &mut [u8]) -> Result<(), Error> {
    Ok(rng().fill(bytes))
}

/// Make a Vec<u8> of the given size
/// containing random material.
pub fn random_vec(len: usize) -> Result<Vec<u8>, Error> {
    let mut v = vec![0; len];
    fill_random(&mut v)?;
    Ok(v)
}

/// Return a uniformly random u32.
pub fn random_u32() -> Result<u32, Error> {
    let mut buf = [0u8; 4];
    fill_random(&mut buf)?;
    codec::decode_u32(&buf).ok_or(Error::General(
        "failed to get random from system".to_string(),
    ))
}
