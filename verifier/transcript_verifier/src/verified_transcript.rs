use super::{
    commitment::{CommitmentOpening, Direction, TranscriptRange},
    doc::verified::VerifiedDoc,
};

/// A notarized TLS transcript which successfully passed verification
#[derive(PartialEq, Debug)]
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
            .map(|opening| {
                // extract enum variant's id and opening bytes
                let (opening_id, opening_bytes) = match opening {
                    CommitmentOpening::LabelsBlake3(opening) => (opening.id(), opening.opening()),
                    #[cfg(test)]
                    CommitmentOpening::SomeFutureVariant(ref opening) => {
                        (opening.id(), opening.opening())
                    }
                };

                // commitment corresponding to the `opening`
                let commitment = &verified_doc.commitments()[opening_id as usize];

                // cloning because we will be draining the bytes of the `opening`
                let mut opening = opening_bytes.clone();

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
            .collect::<Vec<_>>()
            .into_iter()
            .flatten()
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
#[derive(PartialEq, Debug)]
pub struct TranscriptSlice {
    /// A byte range of this slice
    range: TranscriptRange,
    /// A slice covers a byte range in one direction
    direction: Direction,
    /// The actual byte content of the slice
    data: Vec<u8>,
}

impl TranscriptSlice {
    pub(crate) fn new(range: TranscriptRange, direction: Direction, data: Vec<u8>) -> Self {
        Self {
            range,
            direction,
            data,
        }
    }

    pub fn range(&self) -> &TranscriptRange {
        &self.range
    }

    pub fn direction(&self) -> &Direction {
        &self.direction
    }

    pub fn data(&self) -> &Vec<u8> {
        &self.data
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        doc::verified::test::signed_validated_doc_and_pubkey,
        test::{bytes_in_ranges, default_ranges, DEFAULT_PLAINTEXT},
    };
    use rstest::{fixture, rstest};

    #[fixture]
    // Returns a verified doc
    fn verified_doc() -> VerifiedDoc {
        let (validated_doc, pubkey) = signed_validated_doc_and_pubkey();
        VerifiedDoc::from_validated(validated_doc, "tlsnotary.org", Some(pubkey)).unwrap()
    }

    #[rstest]
    // Expects from_verified_doc() to return the expected value
    fn test_from_verified_doc_success(verified_doc: VerifiedDoc) {
        let transcript = VerifiedTranscript::from_verified_doc(verified_doc, "tlsnotary.org");

        let ranges = default_ranges();

        let expected = VerifiedTranscript::new(
            crate::test::TIME,
            "tlsnotary.org".to_string(),
            vec![
                TranscriptSlice::new(
                    ranges[0].clone(),
                    Direction::Sent,
                    bytes_in_ranges(&DEFAULT_PLAINTEXT, &[ranges[0].clone()]),
                ),
                TranscriptSlice::new(
                    ranges[1].clone(),
                    Direction::Sent,
                    bytes_in_ranges(&DEFAULT_PLAINTEXT, &[ranges[1].clone()]),
                ),
                TranscriptSlice::new(
                    ranges[2].clone(),
                    Direction::Received,
                    bytes_in_ranges(&DEFAULT_PLAINTEXT, &[ranges[2].clone()]),
                ),
                TranscriptSlice::new(
                    ranges[3].clone(),
                    Direction::Received,
                    bytes_in_ranges(&DEFAULT_PLAINTEXT, &[ranges[3].clone()]),
                ),
            ],
        );

        assert_eq!(expected, transcript);
    }
}
