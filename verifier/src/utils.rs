use super::{commitment::Range, Error, LabelSeed};
use blake3::Hasher;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

// Given a `substring` and its byte `ranges` within a larger string, computes a (`salt`ed) commitment
// to the garbled circuit labels. The labels are derived from a PRG `seed`.
pub fn compute_label_commitment(
    substring: &[u8],
    ranges: &Vec<Range>,
    seed: &LabelSeed,
    salt: &Vec<u8>,
) -> Result<[u8; 32], Error> {
    // TODO: will need to bring this in harmony with label encoder in mpc-core

    let mut rng = ChaCha20Rng::from_seed(*seed);
    let delta: u128 = rng.gen();
    // we need least-bit-first order, hence reverse()
    let mut bits = u8vec_to_boolvec(substring);
    bits.reverse();
    let mut bits_iter = bits.into_iter();

    // for each bit of opening, expand the zero label at the rng stream offset
    // and, if needed, flip it to the one label, then hash the label
    let mut hasher = Hasher::new();
    for r in ranges {
        // set rng stream offset to the first label in range. +1 accounts for
        // the delta
        rng.set_word_pos(4 * ((r.start() as u128) + 1));

        // expand as many labels as there are bits in the range
        (0..(r.end() - r.start()) * 8).map(|_| {
            let zero_label: u128 = rng.gen();
            let active_label = if bits_iter.next().unwrap() == true {
                zero_label ^ delta
            } else {
                zero_label
            };
            hasher.update(&active_label.to_be_bytes());
        });
    }
    // add salt
    hasher.update(salt);
    Ok(hasher.finalize().into())
}

/// Returns a substring of the original bytestring containing only the bytes in `ranges`
// TODO check len overflow
pub fn bytes_in_ranges(bytestring: &[u8], ranges: &[Range]) -> Vec<u8> {
    let mut substring: Vec<u8> = Vec::new();
    for r in ranges {
        substring.append(&mut bytestring[r.start()..r.end()].to_vec())
    }
    substring
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

pub fn blake3(data: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(data);
    hasher.finalize().into()
}
