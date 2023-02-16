use super::{error::Error, utils::compute_label_commitment, HashCommitment, LabelSeed};
use serde::Serialize;

/// A validated User's commitment to a portion of the notarized data
#[derive(Serialize, Clone, Default)]
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

    /// Verifies this commitment against the opening
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

    #[cfg(test)]
    pub fn set_id(&mut self, id: u32) {
        self.id = id;
    }

    #[cfg(test)]
    pub fn set_typ(&mut self, typ: CommitmentType) {
        self.typ = typ;
    }

    #[cfg(test)]
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
    #[cfg(test)]
    some_future_commitment_type,
}

/// Various supported types of commitment opening
#[derive(Serialize, Clone)]
pub enum CommitmentOpening {
    LabelsBlake3(LabelsBlake3Opening),
    #[cfg(test)]
    SomeFutureVariant(SomeFutureVariantOpening),
}

/// A validated opening for the commitment type [CommitmentType::labels_blake3]
#[derive(Serialize, Clone)]
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

    #[cfg(test)]
    pub fn set_id(&mut self, id: u32) {
        self.id = id;
    }

    pub fn set_opening(&mut self, opening: Vec<u8>) {
        self.opening = opening;
    }

    #[cfg(test)]
    pub fn set_label_seed(&mut self, label_seed: LabelSeed) {
        self.label_seed = label_seed;
    }

    #[cfg(test)]
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

    #[cfg(test)]
    pub fn new_unchecked(start: u32, end: u32) -> Self {
        Self { start, end }
    }
}

#[cfg(test)]
#[derive(Serialize, Clone, Default)]
pub struct SomeFutureVariantOpening {
    id: u32,
    opening: Vec<u8>,
    salt: Vec<u8>,
}

#[cfg(test)]
impl SomeFutureVariantOpening {
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

    pub fn set_id(&mut self, id: u32) {
        self.id = id;
    }

    pub fn set_opening(&mut self, opening: Vec<u8>) {
        self.opening = opening;
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::{commitment::TranscriptRange, doc::validated::test::validated_doc};
    use rstest::{fixture, rstest};

    #[fixture]
    // Returns a correct label commitment / opening pair
    fn get_pair() -> (Commitment, CommitmentOpening) {
        let doc = validated_doc();
        (
            doc.commitments()[0].clone(),
            doc.commitment_openings()[0].clone(),
        )
    }

    #[rstest]
    // Expect verify() to succeed
    fn verify_success(get_pair: (Commitment, CommitmentOpening)) {
        let (commitment, opening) = get_pair;
        assert!(commitment.verify(&opening).is_ok())
    }

    #[rstest]
    // Expect verify() to fail because an opening byte is incorrect
    fn verify_fail_wrong_opening(get_pair: (Commitment, CommitmentOpening)) {
        let (commitment, opening) = get_pair;
        let mut opening = match opening {
            CommitmentOpening::LabelsBlake3(opening) => opening,
            _ => panic!(),
        };
        let mut old_bytes = opening.opening().clone();
        // corrupt one byte
        old_bytes[0] = old_bytes[0].checked_add(1).unwrap_or(0);
        opening.set_opening(old_bytes);

        let opening = CommitmentOpening::LabelsBlake3(opening);

        assert!(commitment.verify(&opening).err().unwrap() == Error::CommitmentVerificationFailed)
    }

    #[rstest]
    // Expect verify() to fail because commitment range is incorrect
    fn verify_fail_wrong_range(get_pair: (Commitment, CommitmentOpening)) {
        let (mut commitment, opening) = get_pair;

        let mut ranges = commitment.ranges().clone();
        ranges[0] = TranscriptRange::new(ranges[0].start() + 1, ranges[0].end() + 1).unwrap();
        commitment.set_ranges(ranges);

        assert!(commitment.verify(&opening).err().unwrap() == Error::CommitmentVerificationFailed)
    }

    #[rstest]
    // Expect verify() to fail because label_seed is incorrect
    fn verify_fail_wrong_seed(get_pair: (Commitment, CommitmentOpening)) {
        let (commitment, opening) = get_pair;

        let mut opening = match opening {
            CommitmentOpening::LabelsBlake3(opening) => opening,
            _ => panic!(),
        };
        let mut seed = *opening.label_seed();
        // corrupt one byte
        seed[0] = seed[0].checked_add(1).unwrap_or(0);
        opening.set_label_seed(seed);

        let opening = CommitmentOpening::LabelsBlake3(opening);

        assert!(commitment.verify(&opening).err().unwrap() == Error::CommitmentVerificationFailed)
    }

    #[rstest]
    // Expect verify() to fail because salt is incorrect
    fn verify_fail_wrong_salt(get_pair: (Commitment, CommitmentOpening)) {
        let (commitment, opening) = get_pair;

        let mut opening = match opening {
            CommitmentOpening::LabelsBlake3(opening) => opening,
            _ => panic!(),
        };
        let mut salt = opening.salt().clone();
        // corrupt one byte
        salt[0] = salt[0].checked_add(1).unwrap_or(0);
        opening.set_salt(salt);

        let opening = CommitmentOpening::LabelsBlake3(opening);

        assert!(commitment.verify(&opening).err().unwrap() == Error::CommitmentVerificationFailed)
    }
}
