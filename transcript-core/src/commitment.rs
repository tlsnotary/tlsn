use super::{error::Error, HashCommitment, LabelSeed};
use serde::Serialize;

/// A User's commitment to a portion of the notarized data
#[derive(Serialize, Clone, Default)]
pub struct Commitment {
    /// This commitment's index in `commitments` of [crate::document::Document]
    id: u32,
    typ: CommitmentType,
    direction: Direction,
    /// The index of this commitment in the Merkle tree of commitments
    merkle_tree_index: u32,
    /// The actual commitment
    commitment: HashCommitment,
    /// The absolute byte ranges within the notarized data. The committed data
    /// is located in those ranges. Ranges do not overlap.
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

    #[cfg(test)]
    pub fn set_id(&mut self, id: u32) {
        self.id = id;
    }

    #[cfg(test)]
    pub fn set_typ(&mut self, typ: CommitmentType) {
        self.typ = typ;
    }

    #[cfg(any(feature = "expose_setters_for_testing", test))]
    pub fn set_ranges(&mut self, ranges: Vec<TranscriptRange>) {
        self.ranges = ranges;
    }

    #[cfg(test)]
    pub fn set_merkle_tree_index(&mut self, merkle_tree_index: u32) {
        self.merkle_tree_index = merkle_tree_index;
    }

    #[cfg(test)]
    pub fn set_commitment(&mut self, commitment: [u8; 32]) {
        self.commitment = commitment;
    }
}

#[derive(Clone, PartialEq, Serialize, Default)]
#[allow(non_camel_case_types)]
pub enum CommitmentType {
    #[default]
    // A blake3 digest of the garbled circuit's active labels. The labels are generated from a PRG seed.
    // For more details on the protocol used to generate this commitment, see
    // https://github.com/tlsnotary/docs-mdbook/blob/main/src/protocol/notarization/public_data_commitment.md
    labels_blake3,
}

/// Various supported types of commitment opening
#[derive(Serialize, Clone)]
pub enum CommitmentOpening {
    LabelsBlake3(LabelsBlake3Opening),
}

/// A validated opening for the commitment type [CommitmentType::labels_blake3]
#[derive(Serialize, Clone, Default)]
pub struct LabelsBlake3Opening {
    /// This commitment opening's index in `commitment_openings` of [crate::document::Document].
    /// The [Commitment] corresponding to this opening has the same id.
    id: u32,
    /// The actual opening of the commitment
    opening: Vec<u8>,
    /// All our commitments are `salt`ed by appending 16 random bytes
    salt: Vec<u8>,
    /// A PRG seeds from which to generate garbled circuit active labels, see
    /// [crate::commitment::CommitmentType::labels_blake3].
    /// It must match `label_seed` in [crate::document::Document].
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

    #[cfg(any(feature = "expose_setters_for_testing", test))]
    pub fn set_id(&mut self, id: u32) {
        self.id = id;
    }

    pub fn set_opening(&mut self, opening: Vec<u8>) {
        self.opening = opening;
    }

    #[cfg(any(feature = "expose_setters_for_testing", test))]
    pub fn set_label_seed(&mut self, label_seed: LabelSeed) {
        self.label_seed = label_seed;
    }

    #[cfg(any(feature = "expose_setters_for_testing", test))]
    pub fn set_salt(&mut self, salt: Vec<u8>) {
        self.salt = salt;
    }
}

#[derive(Serialize, Clone, PartialEq, Default, Debug)]
/// A TLS transcript consists of a stream of bytes which were `Sent` to the server
/// and a stream of bytes which were `Received` from the server . The User creates
/// separate commitments to bytes in each direction.
pub enum Direction {
    #[default]
    Sent,
    Received,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
/// A non-empty half-open range [start, end). Range bounds are ascending i.e. start < end
pub struct TranscriptRange {
    start: u32,
    end: u32,
}

impl TranscriptRange {
    pub fn new(start: u32, end: u32) -> Result<Self, Error> {
        // empty ranges are not allowed
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

    #[cfg(test)]
    pub fn len(&self) -> u32 {
        self.end - self.start
    }

    #[cfg(any(feature = "expose_setters_for_testing", test))]
    pub fn new_unchecked(start: u32, end: u32) -> Self {
        Self { start, end }
    }
}
