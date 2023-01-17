use crate::{
    commitment::{u8_to_boolvec, Range},
    Error, LabelSeed,
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};

// Given the plaintext (the opening) and the seed, compute a (salted) commitment to the garbled circuit labels
// in the byte ranges.
pub fn compute_label_commitment(
    plaintext: &[u8],
    seed: &LabelSeed,
    ranges: &Vec<Range>,
    salt: Vec<u8>,
) -> Result<[u8; 32], Error> {
    // TODO: will need to bring this in harmony with label encoder in mpc-core

    let mut rng = ChaCha20Rng::from_seed(*seed);
    let delta: u128 = rng.gen();
    let mut bits_iter = u8_to_boolvec(plaintext).into_iter();

    // for each bit of opening, expand the zero label at the rng stream offset
    // and, if needed, flip it to the one label, then hash the label
    let mut hasher = Sha256::new();
    for r in ranges {
        // set rng stream offset to the first label in range. +1 accounts for
        // the delta
        rng.set_word_pos(4 * ((r.start as u128) + 1));

        // expand as many labels as there are bits in the range
        (0..(r.end - r.start) * 8).map(|_| {
            let zero_label: u128 = rng.gen();
            let active_label = if bits_iter.next().unwrap() == true {
                zero_label ^ delta
            } else {
                zero_label
            };
            hasher.update(active_label.to_be_bytes());
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
        substring.append(&mut bytestring[r.start..r.end].to_vec())
    }
    substring
}
