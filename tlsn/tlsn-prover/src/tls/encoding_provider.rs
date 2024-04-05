use std::collections::HashMap;

use mpz_core::serialize::CanonicalSerialize;
use mpz_garble::protocol::deap::PeerEncodings;
use mpz_garble_core::{encoding_state, EncodedValue};
use tlsn_core::{
    encoding::EncodingProvider,
    transcript::{SubsequenceIdx, RX_TRANSCRIPT_ID, TX_TRANSCRIPT_ID},
    Direction, Transcript,
};

/// An encoding provider which has all the encodings cached.
pub(crate) struct CachedEncodingProvider {
    encodings: HashMap<String, EncodedValue<encoding_state::Active>>,
}

impl CachedEncodingProvider {
    pub(crate) fn new(encodings: &impl PeerEncodings, transcript: &Transcript) -> Self {
        let tx_ids = (0..transcript.sent().len()).map(|id| format!("tx/{id}"));
        let rx_ids = (0..transcript.received().len()).map(|id| format!("rx/{id}"));

        let ids = tx_ids.chain(rx_ids).collect::<Vec<_>>();
        let id_refs = ids.iter().map(|id| id.as_ref()).collect::<Vec<_>>();

        Self {
            encodings: encodings
                .get_peer_encodings(&id_refs)
                .expect("encodings for all transcript values should be present")
                .into_iter()
                .zip(ids)
                .map(|(encoding, id)| (id, encoding))
                .collect(),
        }
    }
}

impl EncodingProvider for CachedEncodingProvider {
    fn provide_subsequence(&self, idx: &SubsequenceIdx) -> Option<Vec<u8>> {
        let id = match idx.direction() {
            Direction::Sent => TX_TRANSCRIPT_ID,
            Direction::Received => RX_TRANSCRIPT_ID,
        };

        let mut encoding = Vec::with_capacity(idx.len() * 16);
        for byte_id in idx.ranges().iter() {
            let id = format!("{}/{}", id, byte_id);
            encoding.extend(self.encodings.get(&id)?.to_bytes());
        }

        Some(encoding)
    }
}
