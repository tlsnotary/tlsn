use crate::LabelSeed;

use super::error::Error;
use rand::Rng;
use rand_chacha::ChaCha12Rng;
use rand_core::SeedableRng;
use rs_merkle::{algorithms, MerkleProof};
use sha2::{Digest, Sha256};

// A User's commitment to a portion of the TLS transcript
//#[derive(Clone)]
pub struct Commitment {
    pub id: usize,
    pub typ: CommitmentType,
    pub direction: Direction,
    // The index of this commitment in the Merkle tree of commitments
    pub merkle_tree_index: usize,
    // the actual commitment
    pub commitment: [u8; 32],
    // ranges of absolute offsets in the TLS transcript. The committed data
    // is located in those ranges.
    pub ranges: Vec<Range>,
}

impl Commitment {
    pub fn new(
        id: usize,
        typ: CommitmentType,
        direction: Direction,
        commitment: [u8; 32],
        ranges: Vec<Range>,
        merkle_tree_index: usize,
    ) -> Self {
        Self {
            id,
            typ,
            direction,
            commitment,
            ranges,
            merkle_tree_index,
        }
    }

    /// Check this commitment against the opening.
    /// The opening is a (salted) hash of all garbled circuit active labels in the
    /// ranges of the Commitment
    pub fn verify(&self, opening: &CommitmentOpening, seed: &LabelSeed) -> Result<(), Error> {
        // TODO: will change this method to be in agreement with the Label Encoder PR?

        let mut chacha_seed = [0u8; 32];
        chacha_seed.copy_from_slice(seed.value.as_slice());
        let mut rng = ChaCha12Rng::from_seed(chacha_seed);
        let delta: u128 = rng.gen();
        let mut bits_iter = u8_to_boolvec(&opening.opening).into_iter();

        // for each bit of opening, expand the zero label at the rng stream offset
        // and, if needed, flip it to the one label, then hash the label
        let mut hasher = Sha256::new();
        for r in &self.ranges {
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
        let mut salt = [0u8; 16];
        salt.copy_from_slice(opening.salt.as_slice());
        hasher.update(salt);
        let expected: [u8; 32] = hasher.finalize().into();
        if expected != self.commitment {
            return Err(Error::CommitmentVerificationFailed);
        }

        Ok(())
    }
}

#[derive(Clone, PartialEq)]
pub enum CommitmentType {
    // a blake3 hash of the garbled circuit wire labels corresponding to the bits
    // of the commitment opening
    labels_blake3,
}

// Commitment opening contains either the committed value or a zk proof
// about some property of that value
#[derive(Clone, Default)]
pub struct CommitmentOpening {
    /// the id of the [Commitment] corresponding to this opening
    pub id: usize,
    // the actual opening of the commitment. Optional because a zk proof
    // about some property of the opening can be provided instead
    pub opening: Vec<u8>,
    // all our commitments are salted by appending 16 random bytes
    salt: Vec<u8>,
}

#[derive(Clone, PartialEq)]
// A TLS transcript consists of a stream of bytes which were sent to the server (Request)
// and a stream of bytes which were received from the server (Response). The User creates
// separate commitments to bytes in each direction.
pub enum Direction {
    Request,
    Response,
}

#[derive(Clone)]
/// half-open range [start, end). Range bounds are ascending i.e. start < end
pub struct Range {
    pub start: usize,
    pub end: usize,
}

// convert a slice of u8 into a vec of bool in the least-bit-first order
fn u8_to_boolvec(bytes: &[u8]) -> Vec<bool> {
    vec![false; 10]
}
