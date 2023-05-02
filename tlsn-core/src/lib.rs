pub mod commitment;
//pub mod encoder;
pub mod end_entity_cert;
pub mod error;
pub mod handshake_data;
pub mod handshake_summary;
pub(crate) mod inclusion_proof;
pub mod keparams;
pub mod merkle;
pub mod notarized_session;
pub mod pubkey;
pub mod session_artifacts;
pub mod session_data;
pub mod session_header;
pub(crate) mod session_proof;
pub mod signature;
pub mod signer;
pub mod substrings_commitment;
pub mod substrings_opening;
pub(crate) mod substrings_proof;
pub mod transcript;
mod utils;

pub use commitment::Commitment;
pub use end_entity_cert::EndEntityCert;
pub use handshake_data::HandshakeData;
pub use handshake_summary::HandshakeSummary;
pub use inclusion_proof::InclusionProof;
pub use keparams::KEParams;
pub use notarized_session::NotarizedSession;
pub use session_artifacts::SessionArtifacts;
pub use session_data::SessionData;
pub use session_header::{SessionHeader, SessionHeaderMsg};
pub use session_proof::SessionProof;
pub use substrings_commitment::{SubstringsCommitment, SubstringsCommitmentSet};
pub use substrings_opening::SubstringsOpeningSet;
pub use transcript::{Direction, Transcript, TranscriptRange, TranscriptSlice};

pub type HashCommitment = [u8; 32];

/// The maximum allowed total size of all committed data. Used to prevent DoS during verification.
/// (this will cause the verifier to hash up to a max of 1GB * 128 = 128GB of labels if the
/// commitment type is [crate::commitment::Blake3])
const MAX_TOTAL_COMMITTED_DATA: u64 = 1_000_000_000;

#[cfg(test)]
pub mod test {

    use crate::{
        commitment::{Blake3, Commitment},
        //encoder::{ChaChaEncoder, EncoderSeed},
        end_entity_cert::EndEntityCert,
        handshake_data::ServerSignature,
        merkle::MerkleTree,
        pubkey::{KeyType, PubKey},
        signer::Signer,
        substrings_proof::SubstringsProof,
        utils::encode_bytes_in_ranges,
        Direction,
        HandshakeData,
        HandshakeSummary,
        HashCommitment,
        KEParams,
        NotarizedSession,
        SessionArtifacts,
        SessionData,
        SessionHeader,
        SessionHeaderMsg,
        SessionProof,
        SubstringsCommitment,
        SubstringsCommitmentSet,
        Transcript,
        TranscriptRange,
        TranscriptSlice,
    };
    use blake3::Hasher;
    use mpc_garble_core::ChaChaEncoder;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn test() {
        let testdata = crate::end_entity_cert::test::tlsnotary();
        // User's transcript
        let data_sent = "data sent".as_bytes();
        let data_recv = "data received".as_bytes();
        let transcript = Transcript::new(data_sent.to_vec(), data_recv.to_vec());

        // Ranges of plaintext for which the User wants to create a commitment
        let range1 = TranscriptRange::new(0, 2).unwrap();
        let range2 = TranscriptRange::new(1, 3).unwrap();

        // Bytes located in the ranges
        let bytes1 = transcript
            .get_bytes_in_ranges(&[range1.clone()], &Direction::Sent)
            .unwrap();
        let bytes2 = transcript
            .get_bytes_in_ranges(&[range2.clone()], &Direction::Received)
            .unwrap();

        // Plaintext encodings which the User obtained from GC evaluation
        // (for simplicity of this test we instead generate the encodings using the Notary's encoder)
        let notary_encoder_seed = [5u8; 32];
        let notary_encoder = ChaChaEncoder::new(notary_encoder_seed);

        let encodings1 = encode_bytes_in_ranges(
            &notary_encoder,
            &bytes1,
            &[range1.clone()],
            &Direction::Sent,
        );
        let encodings2 = encode_bytes_in_ranges(
            &notary_encoder,
            &bytes2,
            &[range2.clone()],
            &Direction::Received,
        );
        // salt adds entropy to the commitment
        let salt1 = [3u8; 16];
        let salt2 = [4u8; 16];

        // hashing the encodings with the salt produces a commitment
        let mut hasher1 = Hasher::new();
        for e in encodings1 {
            hasher1.update(&e);
        }
        // add salt
        hasher1.update(&salt1);

        let mut hasher2 = Hasher::new();
        for e in encodings2 {
            hasher2.update(&e);
        }
        // add salt
        hasher2.update(&salt2);

        let commitment1_bytes: HashCommitment = hasher1.finalize().into();
        let commitment2_bytes: HashCommitment = hasher2.finalize().into();

        let commitments = vec![
            SubstringsCommitment::new(
                0,
                Commitment::Blake3(Blake3::new(commitment1_bytes)),
                vec![range1.clone()],
                Direction::Sent,
                salt1,
            ),
            SubstringsCommitment::new(
                1,
                Commitment::Blake3(Blake3::new(commitment2_bytes)),
                vec![range2.clone()],
                Direction::Received,
                salt2,
            ),
        ];

        // At the end of the session the User holds these artifacts:

        // time when the TLS handshake began
        let time = testdata.time;

        // merkle tree of all User's commitments (the root of the tree was sent to the Notary earlier)
        let merkle_tree = MerkleTree::from_leaves(&[commitment1_bytes, commitment2_bytes]);

        // encoder seed revealed by the Notary at the end of the label commitment protocol
        let encoder_seed: [u8; 32] = notary_encoder_seed;

        // server ephemeral key (known both to the User and the Notary)
        let ephem_key: PubKey = PubKey::from_bytes(KeyType::P256, &testdata.pubkey).unwrap();

        // handshake data (to which the User sent a commitment earlier)
        let handshake_data = HandshakeData::new(
            EndEntityCert::new(testdata.ee.clone()),
            vec![testdata.ca, testdata.inter],
            KEParams::new(ephem_key.clone(), testdata.cr, testdata.sr),
            ServerSignature::new(testdata.sigalg, testdata.sig),
        );

        // Commitment to the handshake which the User sent at the start of the TLS handshake
        let handshake_commitment = handshake_data.commit().unwrap();

        let artifacts = SessionArtifacts::new(
            time,
            merkle_tree.clone(),
            encoder_seed,
            ephem_key.clone(),
            handshake_data,
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
            HandshakeSummary::new(time + 60, ephem_key, handshake_commitment),
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
            artifacts.handshake_data().clone(),
            transcript,
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
        let handshake_data = session_proof.handshake_data().clone();

        // (if the Notary is the Verifier then no pubkey is required and None is passed)
        let header = SessionHeader::from_msg(header, Some(&pubkey)).unwrap();

        handshake_data
            .verify(header.handshake_summary(), &testdata.dns_name)
            .unwrap();

        let (sent_slices, recv_slices) = substrings_proof.verify(&header).unwrap();

        assert!(sent_slices == vec![TranscriptSlice::new(range1, b"da".to_vec())]);
        assert!(recv_slices == vec![TranscriptSlice::new(range2, b"at".to_vec())])
    }
}
