pub mod garble;
pub mod ot;

#[inline]
pub fn to_proto(&self) -> ProtoBlock {
    ProtoBlock {
        low: self.0 as u64,
        high: (self.0 >> 64) as u64,
    }
}

fn parse_ristretto_key(b: Vec<u8>) -> Result<RistrettoPoint, Vec<u8>> {
    if b.len() != 32 {
        return Err(b);
    }
    let c_point = CompressedRistretto::from_slice(b.as_slice());
    if let Some(point) = c_point.decompress() {
        Ok(point)
    } else {
        Err(b)
    }
}
