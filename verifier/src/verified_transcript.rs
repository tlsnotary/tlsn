use super::{
    commitment::{CommitmentOpening, Direction, Range},
    doc::VerifiedDoc,
};

/// A notarized TLS transcript which successfully passed verification
pub struct VerifiedTranscript {
    /// The time of notarization
    date: u64,
    /// The DNS name of the server with whom the TLS session was notarized
    dns_name: String,
    /// The data which was notarized. It contains decrypted application data without any TLS
    /// record metadata.
    data: Vec<TranscriptSlice>,
}

impl VerifiedTranscript {
    fn new(date: u64, dns_name: String, data: Vec<TranscriptSlice>) -> Self {
        Self {
            date,
            dns_name,
            data,
        }
    }

    /// Creates a [VerifiedTranscript] by extracting relevant fields from a [VerifiedDoc]
    pub(crate) fn from_verified_doc(verified_doc: VerifiedDoc, dns_name: &str) -> Self {
        let transcript_slices: Vec<TranscriptSlice> = verified_doc
            .commitment_openings()
            .iter()
            .flat_map(|opening| {
                // commitment corresponding to the `opening`
                let opening = match opening {
                    CommitmentOpening::LabelsBlake3(opening) => opening,
                };
                let commitment = &verified_doc.commitments()[opening.id() as usize];

                // cloning because we will be draining the bytes of the `opening`
                let mut opening = opening.opening().clone();

                // turn each commitment range into a separate [TranscriptSlice]
                // (note that all commitments are validated and properly sorted)
                let slices: Vec<TranscriptSlice> = commitment
                    .ranges()
                    .iter()
                    .map(|range| {
                        let range_size = range.end() - range.start();
                        let data = opening.drain(0..(range_size as usize)).collect();
                        TranscriptSlice::new(
                            (*range).clone(),
                            (*commitment).direction().clone(),
                            data,
                        )
                    })
                    .collect();

                slices
            })
            .collect();

        VerifiedTranscript::new(
            verified_doc.tls_handshake().signed_handshake().time(),
            dns_name.to_string(),
            transcript_slices,
        )
    }

    pub fn date(&self) -> u64 {
        self.date
    }

    pub fn dns_name(&self) -> &str {
        &self.dns_name
    }

    pub fn data(&self) -> &Vec<TranscriptSlice> {
        &self.data
    }
}

/// Authenticated slice of data
pub struct TranscriptSlice {
    /// A byte range of this slice
    range: Range,
    /// A slice covers a byte range in one direction
    direction: Direction,
    /// The actual byte content of the slice
    data: Vec<u8>,
}

impl TranscriptSlice {
    pub(crate) fn new(range: Range, direction: Direction, data: Vec<u8>) -> Self {
        Self {
            range,
            direction,
            data,
        }
    }

    pub fn range(&self) -> &Range {
        &self.range
    }

    pub fn direction(&self) -> &Direction {
        &self.direction
    }

    pub fn data(&self) -> &Vec<u8> {
        &self.data
    }
}
