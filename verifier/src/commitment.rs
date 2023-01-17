use crate::LabelSeed;

use super::error::Error;
use crate::utils::compute_label_commitment;
use rand::Rng;
use rand_chacha::ChaCha12Rng;
use rand_core::SeedableRng;
use serde;
use sha2::{Digest, Sha256};

// A User's commitment to a portion of the TLS transcript
#[derive(serde::Serialize)]
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
        let expected =
            compute_label_commitment(&opening.opening, seed, &self.ranges, opening.salt.clone())?;

        if expected != self.commitment {
            return Err(Error::CommitmentVerificationFailed);
        }

        Ok(())
    }
}

#[derive(Clone, PartialEq, serde::Serialize)]
pub enum CommitmentType {
    // a blake3 hash of the garbled circuit wire labels corresponding to the bits
    // of the commitment opening
    labels_blake3,
}

// Commitment opening contains either the committed value or a zk proof
// about some property of that value
#[derive(serde::Serialize, Clone, Default)]
pub struct CommitmentOpening {
    /// the id of the [Commitment] corresponding to this opening
    pub id: usize,
    // the actual opening of the commitment. Optional because a zk proof
    // about some property of the opening can be provided instead
    pub opening: Vec<u8>,
    // all our commitments are salted by appending 16 random bytes
    salt: Vec<u8>,
}

impl CommitmentOpening {
    pub fn new(id: usize, opening: Vec<u8>, salt: Vec<u8>) -> Self {
        Self { id, opening, salt }
    }
}

#[derive(serde::Serialize, Clone, PartialEq)]
// A TLS transcript consists of a stream of bytes which were sent to the server (Request)
// and a stream of bytes which were received from the server (Response). The User creates
// separate commitments to bytes in each direction.
pub enum Direction {
    Request,
    Response,
}

#[derive(serde::Serialize, Clone)]
/// half-open range [start, end). Range bounds are ascending i.e. start < end
pub struct Range {
    pub start: usize,
    pub end: usize,
}

impl Range {
    pub fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }
}

// convert a slice of u8 into a vec of bool in the least-bit-first order
pub fn u8_to_boolvec(bytes: &[u8]) -> Vec<bool> {
    // TODO: need to implement
    vec![true; bytes.len() * 8]
}

fn test() {}
