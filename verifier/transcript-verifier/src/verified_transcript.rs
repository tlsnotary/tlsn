use crate::{commitment::Commitment, doc::verified::VerifiedDoc, utils::merge_sorted_slices};
use transcript_core::commitment::{CommitmentOpening, Direction, TranscriptRange};

/// A notarized TLS transcript which successfully passed verification
#[derive(PartialEq, Debug)]
pub struct VerifiedTranscript {
    /// The time of notarization
    date: u64,
    /// The DNS name of the server with whom the TLS session was notarized
    dns_name: String,
    /// The notarized data which was sent to the server. It contains decrypted application data
    /// without any TLS record metadata.
    sent_data: Vec<TranscriptSlice>,
    /// The notarized data which was received from the server. It contains decrypted application data
    /// without any TLS record metadata.
    received_data: Vec<TranscriptSlice>,
}

impl VerifiedTranscript {
    fn new(
        date: u64,
        dns_name: String,
        sent_data: Vec<TranscriptSlice>,
        received_data: Vec<TranscriptSlice>,
    ) -> Self {
        Self {
            date,
            dns_name,
            sent_data,
            received_data,
        }
    }

    /// Creates a [VerifiedTranscript] by extracting relevant fields from a [VerifiedDoc]
    pub(crate) fn from_verified_doc(verified_doc: VerifiedDoc, dns_name: &str) -> Self {
        let time = verified_doc.tls_handshake().signed_handshake().time();
        let pairs = extract_commitment_opening_pairs(verified_doc);

        // separate Sent and Received directions of commitments
        // and break down each pair into [TranscriptSlice]s
        let mut sent_slices: Vec<TranscriptSlice> = pairs
            .iter()
            .filter(|pair| pair.0.direction() == &Direction::Sent)
            .cloned()
            .flat_map(pair_into_slices)
            .collect();

        let mut received_slices: Vec<TranscriptSlice> = pairs
            .iter()
            .filter(|pair| pair.0.direction() == &Direction::Received)
            .cloned()
            .flat_map(pair_into_slices)
            .collect();

        // sort slices by the start bound of its range
        sent_slices.sort_by_key(|slice| slice.range().start());
        received_slices.sort_by_key(|slice| slice.range().start());

        // merge any slices that need merging
        let sent_slices = merge_sorted_slices(sent_slices);
        let received_slices = merge_sorted_slices(received_slices);

        VerifiedTranscript::new(time, dns_name.to_string(), sent_slices, received_slices)
    }

    pub fn date(&self) -> u64 {
        self.date
    }

    pub fn dns_name(&self) -> &str {
        &self.dns_name
    }

    pub fn sent_data(&self) -> &Vec<TranscriptSlice> {
        &self.sent_data
    }

    pub fn received_data(&self) -> &Vec<TranscriptSlice> {
        &self.received_data
    }
}

/// Extracts all pairs of (commitment, corresponding opening bytes) from the document
fn extract_commitment_opening_pairs(verified_doc: VerifiedDoc) -> Vec<(Commitment, Vec<u8>)> {
    verified_doc
        .commitment_openings()
        .iter()
        .map(|opening| {
            // extract enum variant's id and opening bytes
            let (opening_id, opening_bytes) = match opening {
                CommitmentOpening::LabelsBlake3(opening) => (opening.id(), opening.opening()),
            };

            // commitment corresponding to the `opening`
            let commitment = &verified_doc.commitments()[opening_id as usize];
            (commitment.clone(), opening_bytes.clone())
        })
        .collect()
}

/// Break down a (commitment, corresponding opening bytes) pair into [TranscriptSlice]s
/// (note that commitment's ranges have been validated to be non-overlapping and ascending relative
/// to each other)
fn pair_into_slices(pair: (Commitment, Vec<u8>)) -> Vec<TranscriptSlice> {
    let commitment = pair.0;
    let mut opening = pair.1;

    commitment
        .ranges()
        .iter()
        .map(|range| {
            let range_size = range.end() - range.start();
            let data = opening.drain(0..(range_size as usize)).collect();
            TranscriptSlice::new((*range).clone(), data)
        })
        .collect()
}

/// Authenticated slice of data
#[derive(PartialEq, Debug, Clone)]
pub struct TranscriptSlice {
    /// A byte range of this slice
    range: TranscriptRange,
    /// The actual byte content of the slice
    data: Vec<u8>,
}

impl TranscriptSlice {
    pub(crate) fn new(range: TranscriptRange, data: Vec<u8>) -> Self {
        Self { range, data }
    }

    pub fn range(&self) -> &TranscriptRange {
        &self.range
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

        // the first 2 default ranges [5,20] and [20,22] will be merged
        let merged_range = TranscriptRange::new(5, 22).unwrap();

        let expected = VerifiedTranscript::new(
            crate::test::TIME,
            "tlsnotary.org".to_string(),
            vec![TranscriptSlice::new(
                merged_range.clone(),
                bytes_in_ranges(&DEFAULT_PLAINTEXT, &[merged_range]),
            )],
            vec![
                TranscriptSlice::new(
                    ranges[2].clone(),
                    bytes_in_ranges(&DEFAULT_PLAINTEXT, &[ranges[2].clone()]),
                ),
                TranscriptSlice::new(
                    ranges[3].clone(),
                    bytes_in_ranges(&DEFAULT_PLAINTEXT, &[ranges[3].clone()]),
                ),
            ],
        );

        assert_eq!(expected, transcript);
    }

    #[test]
    fn test_pair_into_slices() {
        // create non-overlapping ranges ascending relative to each other
        let ranges = [
            TranscriptRange::new(0, 1).unwrap(),
            TranscriptRange::new(1, 5).unwrap(),
            TranscriptRange::new(5, 10).unwrap(),
            TranscriptRange::new(11, 15).unwrap(),
            TranscriptRange::new(20, 25).unwrap(),
        ];
        let opening = bytes_in_ranges(&DEFAULT_PLAINTEXT, &ranges);

        // create a commitment with the above ranges
        let mut commitment = Commitment::default();
        commitment.set_ranges(ranges.to_vec());

        let expected: Vec<TranscriptSlice> = ranges
            .iter()
            .map(|range| {
                TranscriptSlice::new(
                    range.clone(),
                    bytes_in_ranges(&DEFAULT_PLAINTEXT, &[range.clone()]),
                )
            })
            .collect();

        assert_eq!(expected, pair_into_slices((commitment, opening)));
    }
}
