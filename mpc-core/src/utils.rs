use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use sha2::{Digest, Sha256};

#[inline]
pub fn boolvec_to_u8vec(bv: &[bool]) -> Vec<u8> {
    assert!(bv.len() & 7 == 0);
    let mut v = vec![0u8; bv.len() / 8];
    for (i, b) in bv.iter().enumerate() {
        v[i / 8] |= (*b as u8) << (7 - (i % 8));
    }
    v
}

#[inline]
pub fn u8vec_to_boolvec(v: &[u8]) -> Vec<bool> {
    let mut bv = Vec::with_capacity(v.len() * 8);
    for byte in v.iter() {
        for i in 0..8 {
            bv.push(((byte >> (7 - i)) & 1) != 0);
        }
    }
    bv
}

pub fn boolvec_to_string(v: &[bool]) -> String {
    v.iter().map(|b| (*b as u8).to_string()).collect::<String>()
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

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// XORs 2 slices of bytes of equal length
pub fn xor(a: &[u8], b: &[u8], out: &mut [u8]) {
    assert!(a.len() == b.len() && a.len() == out.len());
    for ((a, b), out) in a.iter().zip(b.iter()).zip(out.iter_mut()) {
        *out = a ^ b;
    }
}

/// Unzips a slice of pairs, returning items corresponding to choice
pub fn choose<T: Copy>(items: &[[T; 2]], choice: &[bool]) -> Vec<T> {
    assert!(items.len() == choice.len(), "arrays are different length");
    items
        .iter()
        .zip(choice)
        .map(|(items, choice)| items[*choice as usize])
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boolvec_to_u8vec() {
        let mut u = vec![false; 16];
        u[7] = true;
        assert_eq!(boolvec_to_u8vec(&u), &256u16.to_be_bytes());

        let v = (0..128)
            .map(|_| rand::random::<bool>())
            .collect::<Vec<bool>>();
        let v_ = boolvec_to_u8vec(&v);
        let v__ = u8vec_to_boolvec(&v_);
        assert_eq!(v, v__);
    }

    #[test]
    fn test_u8vec_to_boolvec() {
        let mut u = vec![false; 16];
        u[7] = true;
        assert_eq!(u8vec_to_boolvec(&256u16.to_be_bytes()), u);

        let v = (0..128).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();
        let v_ = u8vec_to_boolvec(&v);
        let v__ = boolvec_to_u8vec(&v_);
        assert_eq!(v, v__);
    }

    #[test]
    fn test_xor() {
        let a = [2u8; 32];
        let b = [3u8; 32];
        let mut out = [0u8; 32];
        xor(&a, &b, &mut out);
        let expected = [1u8; 32];
        assert_eq!(out, expected);
    }

    #[should_panic]
    #[test]
    fn test_xor_panic() {
        let a = [2u8; 32];
        let b = [3u8; 31];
        let mut out = [0u8; 32];
        xor(&a, &b, &mut out);
    }
}
