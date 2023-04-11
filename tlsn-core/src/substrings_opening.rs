use crate::{
    commitment::Commitment,
    encoder::Block,
    error::Error,
    substrings_commitment::Direction,
    transcript::{TranscriptRange, TranscriptSlice},
    SessionHeader,
};

pub enum SubstringsOpening {
    Blake3(Blake3Opening),
}

impl SubstringsOpening {
    pub fn verify(
        &self,
        header: &SessionHeader,
        commitment: &Commitment,
    ) -> Result<Vec<TranscriptSlice>, Error> {
        match self {
            SubstringsOpening::Blake3(opening) => {
                let labels = header
                    .encoder()
                    .get_labels(opening.opening(), opening.ranges());
                opening.verify(labels, commitment)?
            }
        }
        Ok(self.into_slices())
    }

    pub fn merkle_tree_index(&self) -> u32 {
        match self {
            SubstringsOpening::Blake3(opening) => opening.merkle_tree_index(),
        }
    }

    pub fn direction(&self) -> &Direction {
        match self {
            SubstringsOpening::Blake3(opening) => opening.direction(),
        }
    }

    /// Returns opening bytes split up into slices
    fn into_slices(&self) -> Vec<TranscriptSlice> {
        // TODO: not implemented
        let slice = TranscriptSlice::default();
        vec![slice.clone(), slice.clone()]
    }
}

pub struct Blake3Opening {
    /// The index of this commitment in the Merkle tree of commitments
    merkle_tree_index: u32,
    /// The actual opening bytes
    opening: Vec<u8>,
    /// The absolute byte ranges within the notarized data. The committed data
    /// is located in those ranges. Ranges do not overlap.
    ranges: Vec<TranscriptRange>,
    direction: Direction,
}

impl Blake3Opening {
    pub fn new(
        merkle_tree_index: u32,
        opening: Vec<u8>,
        ranges: &[TranscriptRange],
        direction: Direction,
    ) -> Self {
        Self {
            merkle_tree_index,
            opening,
            ranges: ranges.to_vec(),
            direction,
        }
    }

    pub fn verify(&self, labels: Vec<Block>, commitment: &Commitment) -> Result<(), Error> {
        // TODO: commitment should be Blake3, hash the labels and compare to the commitment
        Ok(())
    }

    pub fn merkle_tree_index(&self) -> u32 {
        self.merkle_tree_index
    }

    pub fn opening(&self) -> &[u8] {
        &self.opening
    }

    pub fn ranges(&self) -> &[TranscriptRange] {
        &self.ranges
    }

    pub fn direction(&self) -> &Direction {
        &self.direction
    }
}
