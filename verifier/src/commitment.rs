use super::{error::Error, utils::compute_label_commitment, HashCommitment, LabelSeed};
use serde::Serialize;

/// A validated User's commitment to a portion of the notarized data
#[derive(Serialize)]
pub struct Commitment {
    /// This commitment's index in `commitments` of [super::UncheckedDoc]
    id: u32,
    typ: CommitmentType,
    direction: Direction,
    /// The index of this commitment in the Merkle tree of commitments
    merkle_tree_index: u32,
    /// The actual commitment
    commitment: HashCommitment,
    /// The absolute byte ranges within the notarized data. The committed data
    /// is located in those ranges.
    ranges: Vec<TranscriptRange>,
}

impl Commitment {
    pub fn new(
        id: u32,
        typ: CommitmentType,
        direction: Direction,
        commitment: HashCommitment,
        ranges: Vec<TranscriptRange>,
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
    pub fn verify(&self, opening: &CommitmentOpening) -> Result<(), Error> {
        let expected = match self.typ {
            CommitmentType::labels_blake3 => {
                let opening = match opening {
                    CommitmentOpening::LabelsBlake3(opening) => opening,
                    // will never happen since we checked that commitment and opening types match
                    #[allow(unreachable_patterns)]
                    _ => return Err(Error::InternalError),
                };

                compute_label_commitment(
                    opening.opening(),
                    &self.ranges,
                    opening.label_seed(),
                    opening.salt(),
                )?
            }
            #[allow(unreachable_patterns)]
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

    pub fn direction(&self) -> &Direction {
        &self.direction
    }

    pub fn merkle_tree_index(&self) -> u32 {
        self.merkle_tree_index
    }

    pub fn commitment(&self) -> [u8; 32] {
        self.commitment
    }

    pub fn ranges(&self) -> &Vec<TranscriptRange> {
        &self.ranges
    }
}

#[derive(Clone, PartialEq, Serialize)]
#[allow(non_camel_case_types)]
pub enum CommitmentType {
    // A blake3 digest of the garbled circuit's active labels. The labels are generated from a PRG seed.
    // For more details on the protocol used to generate this commitment, see
    // https://github.com/tlsnotary/docs-mdbook/blob/main/src/protocol/notarization/public_data_commitment.md
    labels_blake3,
}

/// Various supported types of commitment opening
#[derive(Serialize)]
pub enum CommitmentOpening {
    LabelsBlake3(LabelsBlake3Opening),
}

/// A validated opening for the commitment type [CommitmentType::labels_blake3]
#[derive(Serialize)]
pub struct LabelsBlake3Opening {
    /// This commitment opening's index in `commitment_openings` of [super::doc::UncheckedDoc].
    /// The [Commitment] corresponding to this opening has the same id.
    id: u32,
    /// The actual opening of the commitment
    opening: Vec<u8>,
    /// All our commitments are `salt`ed by appending 16 random bytes
    salt: Vec<u8>,
    /// A PRG seeds from which to generate garbled circuit active labels, see
    /// [crate::commitment::CommitmentType::labels_blake3].
    /// During validation this was checked to match `label_seed` in [super::doc::UncheckedDoc].
    label_seed: LabelSeed,
}

impl LabelsBlake3Opening {
    pub fn new(id: u32, opening: Vec<u8>, salt: Vec<u8>, label_seed: LabelSeed) -> Self {
        Self {
            id,
            opening,
            salt,
            label_seed,
        }
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

    pub fn label_seed(&self) -> &LabelSeed {
        &self.label_seed
    }
}

#[derive(Serialize, Clone, PartialEq)]
/// A TLS transcript consists of a stream of bytes which were `Sent` to the server
/// and a stream of bytes which were `Received` from the server . The User creates
/// separate commitments to bytes in each direction.
pub enum Direction {
    Sent,
    Received,
}

#[derive(Serialize, Clone, Debug)]
/// A half-open range [start, end). Range bounds are ascending i.e. start < end
pub struct TranscriptRange {
    start: u32,
    end: u32,
}

impl TranscriptRange {
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
