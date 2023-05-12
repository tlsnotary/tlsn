//#![deny(missing_docs, unreachable_pub, unused_must_use)]
//#![deny(clippy::all)]
//#![forbid(unsafe_code)]

//! THis crate contains types used by the Prover, the Notary, and the Verifier

pub mod cert;
pub mod commitment;
pub mod end_entity_cert;
pub mod error;
pub mod handshake_data;
pub mod handshake_summary;
pub(crate) mod inclusion_proof;
pub mod keparams;
pub mod merkle;
pub mod notarized_session;
pub mod pubkey;
pub mod session;
pub mod signature;
pub mod signer;
pub mod substrings;
pub mod transcript;
mod utils;

pub use commitment::Commitment;
pub use end_entity_cert::EndEntityCert;
pub use handshake_data::HandshakeData;
pub use handshake_summary::HandshakeSummary;
pub use inclusion_proof::InclusionProof;
pub use keparams::KEData;
pub use notarized_session::NotarizedSession;
pub use session::{
    session_artifacts::SessionArtifacts,
    session_data::SessionData,
    session_header::{SessionHeader, SessionHeaderMsg},
    session_proof::SessionProof,
};
pub use substrings::{
    substrings_commitment::{SubstringsCommitment, SubstringsCommitmentSet},
    substrings_opening::SubstringsOpeningSet,
};
pub use transcript::{Direction, Transcript, TranscriptSlice};

/// The maximum allowed total size of all committed data. Used to prevent DoS during verification.
/// (this will cause the verifier to hash up to a max of 1GB * 128 = 128GB of labels if the
/// commitment type is [crate::commitment::Blake3])
const MAX_TOTAL_COMMITTED_DATA: u64 = 1_000_000_000;

use mpc_core::utils::blake3;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub struct EncodingId(u64);

impl EncodingId {
    /// Create a new encoding ID.
    pub(crate) fn new(id: &str) -> Self {
        let hash = blake3(id.as_bytes());
        Self(u64::from_be_bytes(hash[..8].try_into().unwrap()))
    }

    /// Returns the encoding ID.
    pub(crate) fn to_inner(self) -> u64 {
        self.0
    }
}

#[cfg(test)]
pub mod test {

    use crate::{
        commitment::{Blake3, Commitment},
        handshake_data::ServerSignature,
        merkle::MerkleTree,
        pubkey::{KeyType, PubKey},
        signer::Signer,
        substrings::substrings_proof::SubstringsProof,
        transcript::TranscriptSet,
        Direction, HandshakeData, HandshakeSummary, KEData, NotarizedSession, SessionArtifacts,
        SessionData, SessionHeader, SessionHeaderMsg, SessionProof, SubstringsCommitment,
        SubstringsCommitmentSet, Transcript, TranscriptSlice,
    };
    use mpc_circuits::types::ValueType;
    use mpc_core::commit::HashCommit;
    use mpc_garble_core::{ChaChaEncoder, EncodedValue, Encoder};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use std::ops::Range;

    #[test]
    /// Tests that the commitment creation protool and verification work end-to-end
    fn test_e2e() {
        let testdata = crate::end_entity_cert::test::tlsnotary();
        // User's transcript
        let data_sent = "sent data".as_bytes();
        let data_recv = "received data".as_bytes();
        let transcript_tx = Transcript::new("tx", data_sent.to_vec());
        let transcript_rx = Transcript::new("rx", data_recv.to_vec());

        // Ranges of plaintext for which the User wants to create a commitment
        let range1: Range<u32> = Range { start: 0, end: 2 };
        let range2: Range<u32> = Range { start: 1, end: 3 };

        // Plaintext encodings which the User obtained from GC evaluation
        // (for simplicity of this test we instead generate the encodings using the Notary's encoder)
        let notary_encoder_seed = [5u8; 32];
        let notary_encoder = ChaChaEncoder::new(notary_encoder_seed);

        // active encodings for each byte in range1
        let active_encodings_range1: Vec<EncodedValue<_>> = transcript_tx
            .get_ids(&range1)
            .into_iter()
            .map(|id| notary_encoder.encode_by_type(id.to_inner(), &ValueType::U8))
            .zip(transcript_tx.data()[range1.start as usize..range1.end as usize].to_vec())
            .map(|(enc, value)| enc.select(value).unwrap())
            .collect();

        // Full encodings for each byte in range2
        let active_encodings_range2: Vec<EncodedValue<_>> = transcript_rx
            .get_ids(&range2)
            .into_iter()
            .map(|id| notary_encoder.encode_by_type(id.to_inner(), &ValueType::U8))
            .zip(transcript_rx.data()[range2.start as usize..range2.end as usize].to_vec())
            .map(|(enc, value)| enc.select(value).unwrap())
            .collect();

        let (decommit1, commit1) = active_encodings_range1.hash_commit();
        let (decommit2, commit2) = active_encodings_range2.hash_commit();

        let commitments = vec![
            SubstringsCommitment::new(
                0,
                Commitment::Blake3(Blake3::new(commit1)),
                vec![range1.clone()],
                Direction::Sent,
                *decommit1.nonce(),
            ),
            SubstringsCommitment::new(
                1,
                Commitment::Blake3(Blake3::new(commit2)),
                vec![range2.clone()],
                Direction::Received,
                *decommit2.nonce(),
            ),
        ];

        // At the end of the session the User holds these artifacts:

        // time when the TLS handshake began
        let time = testdata.time;

        // merkle tree of all User's commitments (the root of the tree was sent to the Notary earlier)
        let merkle_tree = MerkleTree::from_leaves(&[commit1, commit2]);

        // encoder seed revealed by the Notary at the end of the label commitment protocol
        let encoder_seed: [u8; 32] = notary_encoder_seed;

        // server ephemeral key (known both to the User and the Notary)
        let ephem_key: PubKey = PubKey::from_bytes(KeyType::P256, &testdata.pubkey).unwrap();

        // handshake data (to which the User sent a commitment earlier)
        let handshake_data = HandshakeData::new(
            testdata.ee.clone(),
            vec![testdata.ca, testdata.inter],
            KEData::new(ephem_key.clone(), testdata.cr, testdata.sr),
            ServerSignature::new(testdata.sigalg, testdata.sig),
        );

        // Commitment to the handshake which the User sent at the start of the TLS handshake
        let (hs_decommitment, hs_commitment) = handshake_data.hash_commit();

        let artifacts = SessionArtifacts::new(
            time,
            merkle_tree.clone(),
            encoder_seed,
            ephem_key.clone(),
            hs_decommitment,
        );

        // Some outer context generates an (ephemeral) signing key for the Notary, e.g.
        let rng = ChaCha20Rng::from_seed([6u8; 32]);
        let signing_key = p256::ecdsa::SigningKey::random(rng);
        let raw_key = signing_key.to_bytes();
        let raw_key = raw_key.as_slice();

        // Notary receives the raw signing key from some outer context
        let signer = Signer::new(KeyType::P256, raw_key).unwrap();
        let pubkey = signer.verifying_key();

        // Notary creates the session header
        assert!(data_sent.len() <= (u32::MAX as usize) && data_recv.len() <= (u32::MAX as usize));

        let header = SessionHeader::new(
            notary_encoder_seed,
            merkle_tree.root().unwrap(),
            data_sent.len() as u32,
            data_recv.len() as u32,
            // the session's end time and TLS handshake start time may be a few mins apart
            HandshakeSummary::new(time + 60, ephem_key, hs_commitment),
        );

        let signature = header.sign(&signer).unwrap();
        // Notary creates a msg and sends it to User
        // (if the Notary is the Verifier then no signature is required and None is passed)
        let msg = SessionHeaderMsg::new(&header, Some(signature));

        //---------------------------------------
        let msg_bytes = bincode::serialize(&msg).unwrap();
        let msg: SessionHeaderMsg = bincode::deserialize(&msg_bytes).unwrap();
        //---------------------------------------

        // User verifies the header and stores it with the signature in NotarizedSession
        let header = SessionHeader::from_msg(&msg, Some(&pubkey)).unwrap();
        header.check_artifacts(&artifacts).unwrap();
        let signature = msg.signature().cloned();

        let data = SessionData::new(
            artifacts.handshake_data_decommitment().clone(),
            TranscriptSet::new(&[transcript_tx, transcript_rx]),
            artifacts.merkle_tree().clone(),
            SubstringsCommitmentSet::new(commitments),
        );
        let session = NotarizedSession::new(header, signature, data);

        // User converts NotarizedSession into SessionProof and SubstringsProof and sends them to the Verifier
        let session_proof = session.session_proof();
        let substrings_proof = session.generate_substring_proof([0, 1].to_vec()).unwrap();

        //---------------------------------------
        let session_proof_bytes = bincode::serialize(&session_proof).unwrap();
        let substrings_proof_bytes = bincode::serialize(&substrings_proof).unwrap();
        let session_proof: SessionProof = bincode::deserialize(&session_proof_bytes).unwrap();
        let substrings_proof: SubstringsProof =
            bincode::deserialize(&substrings_proof_bytes).unwrap();
        //---------------------------------------

        // The Verifier does:
        let header = session_proof.header();
        let handshake_data_decommitment = session_proof.handshake_data_decommitment().clone();

        // (if the Notary is the Verifier then no pubkey is required and None is passed)
        let header = SessionHeader::from_msg(header, Some(&pubkey)).unwrap();

        // verify the decommitment against the commitment which the Notary signed
        handshake_data_decommitment
            .verify(header.handshake_summary().handshake_commitment())
            .unwrap();

        handshake_data_decommitment
            .data()
            .clone()
            .verify(header.handshake_summary(), &testdata.dns_name)
            .unwrap();

        let (sent_slices, recv_slices) = substrings_proof.verify(&header).unwrap();

        assert!(sent_slices == vec![TranscriptSlice::new(range1, b"se".to_vec())]);
        assert!(recv_slices == vec![TranscriptSlice::new(range2, b"ec".to_vec())])
    }
}
