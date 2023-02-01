use super::{error::Error, utils::compute_label_commitment, HashCommitment, LabelSeed};
use serde::Serialize;
use std::any::Any;

/// A User's commitment to a portion of the notarized data
#[derive(Serialize)]
pub struct Commitment {
    /// This commitment's index in `commitments` of [super::UncheckedDoc]
    id: u32,
    typ: CommitmentType,
    direction: Direction,
    // The index of this commitment in the Merkle tree of commitments
    merkle_tree_index: u32,
    // The actual commitment
    commitment: HashCommitment,
    // The absolute byte ranges within the notarized data. The committed data
    // is located in those ranges.
    ranges: Vec<Range>,
}

impl Commitment {
    pub fn new(
        id: u32,
        typ: CommitmentType,
        direction: Direction,
        commitment: HashCommitment,
        ranges: Vec<Range>,
        merkle_tree_index: u32,
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

    /// Verifies this commitment against the opening. `extra_data` holds extra data specific
    /// to the commitment type.
    pub fn verify(
        &self,
        opening: &CommitmentOpening,
        extra_data: Box<dyn Any>,
    ) -> Result<(), Error> {
        let expected = match self.typ {
            CommitmentType::labels_blake3 => {
                let seed = match extra_data.downcast::<LabelSeed>() {
                    Ok(seed) => seed,
                    Err(_) => return Err(Error::InternalError),
                };

                compute_label_commitment(&opening.opening, &self.ranges, &seed, opening.salt())?
            }
            _ => return Err(Error::InternalError),
        };

        if expected != self.commitment {
            return Err(Error::CommitmentVerificationFailed);
        }

        Ok(())
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn typ(&self) -> &CommitmentType {
        &self.typ
    }

    pub fn merkle_tree_index(&self) -> u32 {
        self.merkle_tree_index
    }

    pub fn commitment(&self) -> [u8; 32] {
        self.commitment
    }

    pub fn ranges(&self) -> &Vec<Range> {
        &self.ranges
    }
}

#[derive(Clone, PartialEq, Serialize)]
pub enum CommitmentType {
    // A blake3 digest of the garbled circuit's active labels. The labels are generated from a PRG seed.
    // For more details on the protocol used to generate this commitment, see
    // https://github.com/tlsnotary/docs-mdbook/blob/main/src/protocol/notarization/public_data_commitment.md
    labels_blake3,
}

/// Commitment opening contains the committed value
#[derive(Serialize)]
pub struct CommitmentOpening {
    /// This commitment opening's index in `commitment_openings` of [super::doc::UncheckedDoc].
    /// The [Commitment] corresponding to this opening has the same id.
    id: u32,
    // the actual opening of the commitment
    opening: Vec<u8>,
    // all our commitments are `salt`ed by appending 16 random bytes
    salt: Vec<u8>,
}

impl CommitmentOpening {
    pub fn new(id: u32, opening: Vec<u8>, salt: Vec<u8>) -> Self {
        Self { id, opening, salt }
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn opening(&self) -> &Vec<u8> {
        &self.opening
    }

    pub fn salt(&self) -> &Vec<u8> {
        &self.salt
    }
}

#[derive(Serialize, Clone, PartialEq)]
// A TLS transcript consists of a stream of bytes which were `Sent` to the server
// and a stream of bytes which were `Received` from the server . The User creates
// separate commitments to bytes in each direction.
pub enum Direction {
    Sent,
    Received,
}

#[derive(Serialize, Clone, Debug)]
/// A half-open range [start, end). Range bounds are ascending i.e. start < end
pub struct Range {
    start: u32,
    end: u32,
}

impl Range {
    pub fn new(start: u32, end: u32) -> Result<Self, Error> {
        if start >= end {
            return Err(Error::RangeInvalid);
        }
        Ok(Self { start, end })
    }

    pub fn start(&self) -> u32 {
        self.start
    }

    pub fn end(&self) -> u32 {
        self.end
    }
}
