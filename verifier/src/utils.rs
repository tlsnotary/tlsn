use super::{commitment::Range, label_encoder::ChaChaEncoder, Error, HashCommitment, LabelSeed};
use blake3::Hasher;

/// Given a `substring` and its byte `ranges` within a larger string, computes a (`salt`ed) commitment
/// to the garbled circuit labels. The labels are derived from a PRG `seed`.
/// `ranges` are ordered ascendingly relative to each other.
///
/// * cipher_block_size - The size of one block of the cipher which was computed inside the garbled
///                       circuit (16 bytes for AES, 64 bytes for ChaCha)
pub(crate) fn compute_label_commitment(
    substring: &[u8],
    ranges: &[Range],
    seed: &LabelSeed,
    salt: &[u8],
    cipher_block_size: usize,
) -> Result<HashCommitment, Error> {
    let mut enc = ChaChaEncoder::new(*seed);

    // making a copy of the substring because we will be drain()ing it
    let mut bytestring = substring.to_vec();

    let mut hasher = Hasher::new();
    for r in ranges {
        let block_ranges = split_into_block_ranges(r, cipher_block_size);
        for br in &block_ranges {
            let range_size = br.end() - br.start();
            let bytes_in_range: Vec<u8> = bytestring.drain(0..range_size).collect();

            // convert bytes in the range into bits in lsb0 order
            let mut bits = u8vec_to_boolvec(&bytes_in_range);
            bits.reverse();
            let mut bits_iter = bits.into_iter();

            // due to lsb0 ordering of labels, we need to flip the range bounds
            let flipped_range = flip_range(br, cipher_block_size);

            // derive as many label pairs as there are bits in the range
            for i in flipped_range.start() * 8..flipped_range.end() * 8 {
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
    }
    // add salt
    hasher.update(salt);
    Ok(hasher.finalize().into())
}

/// Converts a u8 vec into an msb0 bool vec
/// (copied from tlsn/utils)
#[inline]
pub(crate) fn u8vec_to_boolvec(v: &[u8]) -> Vec<bool> {
    let mut bv = Vec::with_capacity(v.len() * 8);
    for byte in v.iter() {
        for i in 0..8 {
            bv.push(((byte >> (7 - i)) & 1) != 0);
        }
    }
    bv
}

/// Given the (validated) global `range` which covers multiple blocks of `block_size` each, splits
/// up the global `range` into multiple ranges each covering one block.
/// E.g. if the global `range` is [5, 35) and the `block_size` is 16, the returned ranges will be:
/// [5, 16) , [16, 32), [32, 35)
pub(crate) fn split_into_block_ranges(range: &Range, block_size: usize) -> Vec<Range> {
    let range_size = range.end() - range.start();

    // if the first block is only partially covered by the global range, store the
    // partially covered size, otherwise, if it is fully covered, store 0.
    let first_partial_size = {
        let offset_from_block_start = range.start() % block_size;
        if offset_from_block_start != 0 {
            let potentially_covered_size = block_size - offset_from_block_start;
            if potentially_covered_size > range_size {
                // there is only one partially covered block in the global range
                range_size
            } else {
                // potentially covered size is the actual covered size
                potentially_covered_size
            }
        } else {
            // the first block is fully covered by the global range
            0
        }
    };

    // if the last block is only partially covered by the global range, store the
    // partially covered size, otherwise, if it is fully covered or if there is only one block
    // total, store 0.
    let last_partial_size = {
        if first_partial_size == range_size {
            // there is only one partially covered block in the global range
            0
        } else {
            range.end() % block_size
        }
    };

    let mut block_ranges: Vec<Range> = Vec::new();
    let mut start = range.start();
    let mut end = range.end();

    let first_partial_range: Option<Range> = if first_partial_size > 0 {
        // save original start
        let orig_start = start;
        // adjust the start of the global range
        start += first_partial_size;

        Some(Range::new(orig_start, orig_start + first_partial_size))
    } else {
        None
    };

    let last_partial_range: Option<Range> = if last_partial_size > 0 {
        // save original end
        let orig_end = end;
        // adjust the end of the global range
        end -= last_partial_size;

        Some(Range::new(orig_end - last_partial_size, orig_end))
    } else {
        None
    };

    // now the global range covers only the full blocks
    let full_block_count = (end - start) / block_size;
    for i in 0..full_block_count {
        // push full block ranges
        block_ranges.push(Range::new(
            start + i * block_size,
            start + (i + 1) * block_size,
        ));
    }

    // if there were any partial ranges, insert them
    if let Some(r) = first_partial_range {
        block_ranges.insert(0, r)
    };
    if let Some(r) = last_partial_range {
        block_ranges.push(r)
    };

    block_ranges
}

/// Given a byte `range` spanning only one block of `block_size`, returns a new
/// range which covers the same block's bytes after the block's bit ordering is changed to lsb0
/// (the block is initially in msb0).
///
/// E.g. if the original `range` is [33, 39) and `block_size` is 16, the result will be [41, 47)
pub(crate) fn flip_range(range: &Range, block_size: usize) -> Range {
    // round down to the nearest multiple of `block_size`
    let block_start_boundary = (range.start() / block_size) * block_size;
    let block_end_boundary = block_start_boundary + block_size;

    // how far the range bounds are shifted from the block boundaries?
    let shift_from_the_start = range.start() - block_start_boundary;
    let shift_from_the_end = block_end_boundary - range.end();

    Range::new(
        block_start_boundary + shift_from_the_end,
        block_end_boundary - shift_from_the_start,
    )
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
        let mut u = vec![false; 16];
        u[7] = true;
        assert_eq!(u8vec_to_boolvec(&256u16.to_be_bytes()), u);
    }

    #[test]
    fn test_split_into_block_ranges() {
        // first partial block, last partial block, full middle block
        let r = Range::new(5, 35);
        let out = split_into_block_ranges(&r, 16);
        let expected = "[Range { start: 5, end: 16 }, Range { start: 16, end: 32 }, Range { start: 32, end: 35 }]";
        assert_eq!(expected, format!("{:?}", out));

        // first partial block, last partial block, no middle blocks
        let r = Range::new(5, 25);
        let out = split_into_block_ranges(&r, 16);
        let expected = "[Range { start: 5, end: 16 }, Range { start: 16, end: 25 }]";
        assert_eq!(expected, format!("{:?}", out));

        // only one partial block
        let r = Range::new(5, 10);
        let out = split_into_block_ranges(&r, 16);
        let expected = "[Range { start: 5, end: 10 }]";
        assert_eq!(expected, format!("{:?}", out));

        // only one full block at 0 offset
        let r = Range::new(0, 16);
        let out = split_into_block_ranges(&r, 16);
        let expected = "[Range { start: 0, end: 16 }]";
        assert_eq!(expected, format!("{:?}", out));

        // only one full block at non-zero offset
        let r = Range::new(16, 32);
        let out = split_into_block_ranges(&r, 16);
        let expected = "[Range { start: 16, end: 32 }]";
        assert_eq!(expected, format!("{:?}", out));

        // first block full, last block partial
        let r = Range::new(16, 33);
        let out = split_into_block_ranges(&r, 16);
        let expected = "[Range { start: 16, end: 32 }, Range { start: 32, end: 33 }]";
        assert_eq!(expected, format!("{:?}", out));

        // first block partial, last block full
        let r = Range::new(15, 32);
        let out = split_into_block_ranges(&r, 16);
        let expected = "[Range { start: 15, end: 16 }, Range { start: 16, end: 32 }]";
        assert_eq!(expected, format!("{:?}", out));
    }

    #[test]
    fn test_flip_range() {
        // block start and end match range start and end
        let r = Range::new(16, 32);
        let out = flip_range(&r, 16);
        let expected = "Range { start: 16, end: 32 }";
        assert_eq!(expected, format!("{:?}", out));

        // only start matches
        let r = Range::new(16, 30);
        let out = flip_range(&r, 16);
        let expected = "Range { start: 18, end: 32 }";
        assert_eq!(expected, format!("{:?}", out));

        // only end matches
        let r = Range::new(20, 32);
        let out = flip_range(&r, 16);
        let expected = "Range { start: 16, end: 28 }";
        assert_eq!(expected, format!("{:?}", out));

        // neither start nor end match
        let r = Range::new(33, 39);
        let out = flip_range(&r, 16);
        let expected = "Range { start: 41, end: 47 }";
        assert_eq!(expected, format!("{:?}", out));
    }
}
