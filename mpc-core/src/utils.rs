use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};

#[inline]
pub fn boolvec_to_u8vec(bv: &[bool]) -> Vec<u8> {
    let offset = if bv.len() % 8 == 0 { 0 } else { 1 };
    let mut v = vec![0u8; bv.len() / 8 + offset];
    for (i, b) in bv.iter().enumerate() {
        v[i / 8] |= (*b as u8) << (i % 8);
    }
    v
}

#[inline]
pub fn u8vec_to_boolvec(v: &[u8]) -> Vec<bool> {
    let mut bv = Vec::with_capacity(v.len() * 8);
    for byte in v.iter() {
        for i in 0..8 {
            bv.push((1 << i) & byte != 0);
        }
    }
    bv
}

pub fn boolvec_to_string(v: &[bool]) -> String {
    v.iter().map(|b| (*b as u8).to_string()).collect::<String>()
}

pub fn transpose(m: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let bits: Vec<Vec<bool>> = m.iter().map(|row| u8vec_to_boolvec(row)).collect();
    let col_count = bits[0].len();
    let row_count = bits.len();

    let mut bits_: Vec<Vec<bool>> = vec![vec![false; row_count]; col_count];
    let mut m_: Vec<Vec<u8>> = Vec::with_capacity(col_count);

    for j in 0..row_count {
        for i in 0..col_count {
            bits_[i][j] = bits[j][i];
        }
    }

    for row in bits_.iter() {
        m_.push(boolvec_to_u8vec(row));
    }

    m_
}

#[inline]
pub fn parse_ristretto_key(b: Vec<u8>) -> Result<RistrettoPoint, std::io::Error> {
    if b.len() != 32 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid RistrettoPoint, should be length 32: {:?}", b),
        ));
    }
    let c_point = CompressedRistretto::from_slice(b.as_slice());
    if let Some(point) = c_point.decompress() {
        Ok(point)
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid RistrettoPoint: {:?}", b),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::Block;
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;

    #[test]
    fn test_transpose() {
        let mut rng = ChaCha12Rng::from_entropy();
        let a: Vec<Vec<u8>> = (0..256)
            .map(|_| Vec::from(Block::random(&mut rng).to_be_bytes()))
            .collect();
        let b = transpose(&a);
        assert_eq!(a, transpose(&b));
    }

    #[test]
    fn test_boolvec_to_u8vec() {
        let v = (0..128)
            .map(|_| rand::random::<bool>())
            .collect::<Vec<bool>>();
        let v_ = boolvec_to_u8vec(&v);
        let v__ = u8vec_to_boolvec(&v_);
        assert_eq!(v, v__);
    }

    #[test]
    fn test_u8vec_to_boolvec() {
        let v = (0..128).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();
        let v_ = u8vec_to_boolvec(&v);
        let v__ = boolvec_to_u8vec(&v_);
        assert_eq!(v, v__);
    }
}
