use blake3::Hasher;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};

#[inline]
pub fn parse_ristretto_key(b: Vec<u8>) -> Result<RistrettoPoint, std::io::Error> {
    if b.len() != 32 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid RistrettoPoint, should be length 32: {:?}", b),
        ));
    }
    let c_point = CompressedRistretto::from_slice(b.as_slice()).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid RistrettoPoint: {:?}", e),
        )
    })?;
    if let Some(point) = c_point.decompress() {
        Ok(point)
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid RistrettoPoint: {:?}", b),
        ))
    }
}

pub fn blake3(data: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(data);
    hasher.finalize().into()
}
