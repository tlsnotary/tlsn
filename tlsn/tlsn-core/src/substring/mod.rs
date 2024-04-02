use crate::{
    attestation::{AttestationBody, Field},
    encoding::EncodingProof,
    hash::PlaintextHashOpening,
    transcript::PartialTranscript,
};

/// A proof of substrings in a transcript.
pub struct SubstringsProof {
    encoding: Option<EncodingProof>,
    hash_openings: Vec<PlaintextHashOpening>,
}

impl SubstringsProof {
    /// Verifies the proof using the attestation body.
    ///
    /// Returns the partial sent and received transcripts, respectively.
    ///
    /// # Arguments
    ///
    /// * `attestation_body` - The attestation body to verify against.
    pub fn verify(
        self,
        attestation_body: &AttestationBody,
    ) -> Result<(PartialTranscript, PartialTranscript), ()> {
        let info = attestation_body.get_info().unwrap();

        let mut sent = PartialTranscript::new(info.transcript_length.sent as usize, vec![]);
        let mut recv = PartialTranscript::new(info.transcript_length.received as usize, vec![]);

        // Verify encoding proof.
        if let Some(proof) = self.encoding {
            let commitment = attestation_body.get_encoding_commitment().unwrap();

            let (sent_, recv_) = proof.verify(&info.transcript_length, commitment).unwrap();
            sent.union(&sent_);
            recv.union(&recv_);
        }

        // Verify hash openings.
        {
            let mut sent_slices = Vec::new();
            let mut recv_slices = Vec::new();
            for opening in self.hash_openings {
                let Field::PlaintextHash(commitment) =
                    attestation_body.get(opening.commitment_id()).unwrap()
                else {
                    panic!();
                };

                let subseq = opening.verify(commitment).unwrap();
                match subseq.idx.direction {
                    crate::Direction::Sent => {
                        sent_slices.extend(subseq.into_slices());
                    }
                    crate::Direction::Received => {
                        recv_slices.extend(subseq.into_slices());
                    }
                }
            }
            let sent_ = PartialTranscript::new(info.transcript_length.sent as usize, sent_slices);
            let recv_ =
                PartialTranscript::new(info.transcript_length.received as usize, recv_slices);

            sent.union(&sent_);
            recv.union(&recv_);
        }

        Ok((sent, recv))
    }
}
