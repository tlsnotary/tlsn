use crate::{error::Error, utils::compute_label_commitment};
use serde::Serialize;
use transcript_core::{
    commitment::{CommitmentOpening, CommitmentType, Direction, TranscriptRange},
    HashCommitment,
};

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
    /// is located in those ranges. Ranges do not overlap but may be adjacent.
    ranges: Vec<TranscriptRange>,
}

impl Commitment {
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

impl std::convert::From<transcript_core::commitment::Commitment> for Commitment {
    fn from(c: transcript_core::commitment::Commitment) -> Self {
        Commitment {
            id: c.id(),
            typ: c.typ().clone(),
            direction: c.direction().clone(),
            merkle_tree_index: c.merkle_tree_index(),
            commitment: c.commitment(),
            ranges: c.ranges().clone(),
        }
    }
}

#[cfg(test)]
pub mod test {
    use crate::{
        commitment::{Commitment, TranscriptRange},
        doc::validated::test::validated_doc,
        error::Error,
    };
    use rstest::{fixture, rstest};
    use transcript_core::commitment::CommitmentOpening;

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
        };
        let mut salt = opening.salt().clone();
        // corrupt one byte
        salt[0] = salt[0].checked_add(1).unwrap_or(0);
        opening.set_salt(salt);

        let opening = CommitmentOpening::LabelsBlake3(opening);

        assert!(commitment.verify(&opening).err().unwrap() == Error::CommitmentVerificationFailed)
    }
}
