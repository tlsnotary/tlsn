use super::{commitment::Range, label_encoder::ChaChaEncoder, Error, HashCommitment, LabelSeed};
use blake3::Hasher;

/// Given a `substring` and its byte `ranges` within a larger string, computes a (`salt`ed) commitment
/// to the garbled circuit labels. The labels are derived from a PRG `seed`.
/// `ranges` are ordered ascendingly relative to each other.
pub(crate) fn compute_label_commitment(
    substring: &[u8],
    ranges: &[Range],
    seed: &LabelSeed,
    salt: &[u8],
) -> Result<HashCommitment, Error> {
    let mut enc = ChaChaEncoder::new(*seed);

    // making a copy of the substring because we will be drain()ing it
    let mut bytestring = substring.to_vec();

    let mut hasher = Hasher::new();
    for r in ranges {
        let range_size = r.end() - r.start();
        let bytes_in_range: Vec<u8> = bytestring.drain(0..range_size).collect();

        // convert bytes in the range into bits in lsb0 order
        let bits = u8vec_to_boolvec(&bytes_in_range);
        let mut bits_iter = bits.into_iter();

        // derive as many label pairs as there are bits in the range
        for i in r.start() * 8..r.end() * 8 {
            let label_pair = enc.encode(i);
            let bit = match bits_iter.next() {
                Some(bit) => bit,
                // should never happen since this method is only called with ranges validated
                // to correspond to the size of the substring
                None => return Err(Error::InternalError),
            };
            let active_label = if bit { label_pair[1] } else { label_pair[0] };

            hasher.update(&active_label.inner().to_be_bytes());
        }
    }
    // add salt
    hasher.update(salt);
    Ok(hasher.finalize().into())
}

/// Converts a u8 vec into an lsb0 bool vec
#[inline]
pub(crate) fn u8vec_to_boolvec(v: &[u8]) -> Vec<bool> {
    let mut bv = Vec::with_capacity(v.len() * 8);
    for byte in v.iter() {
        for i in 0..8 {
            bv.push(((byte >> i) & 1) != 0);
        }
    }
    bv
}

/// Outputs blake3 digest
pub(crate) fn blake3(data: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Returns a substring of the original `bytestring` containing only the bytes in `ranges`.
/// This method is only called with validated `ranges` which do not exceed the size of the
/// `bytestring`.
#[cfg(test)]
pub(crate) fn bytes_in_ranges(bytestring: &[u8], ranges: &[Range]) -> Vec<u8> {
    let mut substring: Vec<u8> = Vec::new();
    for r in ranges {
        substring.append(&mut bytestring[r.start()..r.end()].to_vec())
    }
    substring
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_u8vec_to_boolvec() {
        let mut u = vec![false; 8];
        u[0] = true;
        u[2] = true;
        u[4] = true;
        u[7] = true;
        let res = u8vec_to_boolvec(&149u8.to_be_bytes());
        assert_eq!(res, u);

        let mut u = vec![false; 16];
        u[0] = true;
        u[9] = true;
        let res = u8vec_to_boolvec(&258u16.to_be_bytes());
        assert_eq!(res, u);
    }
}
