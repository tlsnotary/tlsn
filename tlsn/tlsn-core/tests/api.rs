use std::{
    ops::Range,
    time::{Duration, UNIX_EPOCH},
};

use p256::ecdsa::{
    signature::{SignerMut, Verifier},
    Signature as P256Signature, SigningKey,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use tls_core::{
    cert::ServerCertDetails,
    handshake::HandshakeData,
    ke::ServerKxDetails,
    msgs::{enums::SignatureScheme, handshake::DigitallySignedStruct},
};

use mpz_circuits::types::ValueType;
use mpz_core::{commit::HashCommit, serialize::CanonicalSerialize, value::ValueId};
use mpz_garble_core::{ChaChaEncoder, EncodedValue, Encoder};

use tlsn_core::{
    commitment::{Blake3, Commitment},
    fixtures,
    merkle::MerkleTree,
    msg::SignedSessionHeader,
    signature::Signature,
    substrings::proof::SubstringsProof,
    Direction, HandshakeSummary, NotarizedSession, SessionArtifacts, SessionData, SessionHeader,
    SessionProof, SubstringsCommitment, SubstringsCommitmentSet, Transcript,
};

#[test]
/// Tests that the commitment creation protocol and verification work end-to-end
fn test_api() {
    let testdata = crate::fixtures::cert::tlsnotary();
    // Prover's transcript
    let data_sent = "sent data".as_bytes();
    let data_recv = "received data".as_bytes();
    let transcript_tx = Transcript::new("tx", data_sent.to_vec());
    let transcript_rx = Transcript::new("rx", data_recv.to_vec());

    // Ranges of plaintext for which the Prover wants to create a commitment
    let range1: Range<u32> = Range { start: 0, end: 2 };
    let range2: Range<u32> = Range { start: 1, end: 3 };

    // Plaintext encodings which the Prover obtained from GC evaluation
    // (for simplicity of this test we instead generate the encodings using the Notary's encoder)
    let notary_encoder_seed = [5u8; 32];
    let notary_encoder = ChaChaEncoder::new(notary_encoder_seed);

    // active encodings for each byte in range1
    let active_encodings_range1: Vec<EncodedValue<_>> = transcript_tx
        .get_ids(&range1)
        .into_iter()
        .map(|id| notary_encoder.encode_by_type(ValueId::new(&id).to_u64(), &ValueType::U8))
        .zip(transcript_tx.data()[range1.start as usize..range1.end as usize].to_vec())
        .map(|(enc, value)| enc.select(value).unwrap())
        .collect();

    // Full encodings for each byte in range2
    let active_encodings_range2: Vec<EncodedValue<_>> = transcript_rx
        .get_ids(&range2)
        .into_iter()
        .map(|id| notary_encoder.encode_by_type(ValueId::new(&id).to_u64(), &ValueType::U8))
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

    // At the end of the session the Prover holds these artifacts:

    // time when the TLS handshake began
    let time = testdata.time;

    // merkle tree of all Prover's commitments (the root of the tree was sent to the Notary earlier)
    let merkle_tree = MerkleTree::from_leaves(&[commit1, commit2]).unwrap();

    // encoder seed revealed by the Notary at the end of the label commitment protocol
    let encoder_seed: [u8; 32] = notary_encoder_seed;

    // server ephemeral key (known both to the Prover and the Notary)
    let ephem_key = testdata.pubkey.clone();

    // handshake data (to which the Prover sent a commitment earlier)
    let handshake_data = HandshakeData::new(
        ServerCertDetails::new(
            vec![
                testdata.ee.clone(),
                testdata.inter.clone(),
                testdata.ca.clone(),
            ],
            vec![],
            None,
        ),
        ServerKxDetails::new(
            testdata.kx_params(),
            DigitallySignedStruct::new(SignatureScheme::RSA_PKCS1_SHA256, testdata.sig.clone()),
        ),
        testdata.cr,
        testdata.sr,
    );

    // Commitment to the handshake which the Prover sent at the start of the TLS handshake
    let (hs_decommitment, hs_commitment) = handshake_data.hash_commit();

    let artifacts = SessionArtifacts::new(
        time,
        merkle_tree.clone(),
        encoder_seed,
        ephem_key.clone(),
        hs_decommitment,
    );

    // Some outer context generates an (ephemeral) signing key for the Notary, e.g.
    let mut rng = ChaCha20Rng::from_seed([6u8; 32]);
    let signing_key = SigningKey::random(&mut rng);
    let raw_key = signing_key.to_bytes();

    // Notary receives the raw signing key from some outer context
    let mut signer = SigningKey::from_bytes(&raw_key).unwrap();
    let notary_pubkey = signer.verifying_key().clone();

    // Notary creates the session header
    assert!(data_sent.len() <= (u32::MAX as usize) && data_recv.len() <= (u32::MAX as usize));

    let header = SessionHeader::new(
        notary_encoder_seed,
        merkle_tree.root(),
        data_sent.len() as u32,
        data_recv.len() as u32,
        // the session's end time and TLS handshake start time may be a few mins apart
        HandshakeSummary::new(time + 60, ephem_key, hs_commitment),
    );

    let signature: P256Signature = signer.sign(&header.to_bytes());
    // Notary creates a msg and sends it to Prover
    let msg = SignedSessionHeader {
        header,
        signature: signature.into(),
    };

    //---------------------------------------
    let msg_bytes = bincode::serialize(&msg).unwrap();
    let SignedSessionHeader { header, signature } = bincode::deserialize(&msg_bytes).unwrap();
    //---------------------------------------

    // Prover verifies the signature
    #[allow(irrefutable_let_patterns)]
    if let Signature::P256(signature) = signature {
        notary_pubkey
            .verify(&header.to_bytes(), &signature)
            .unwrap();
    } else {
        panic!("Notary signature is not P256");
    };

    // Prover verifies the header and stores it with the signature in NotarizedSession
    header
        .verify(
            artifacts.time(),
            artifacts.server_public_key(),
            &artifacts.merkle_tree().root(),
            artifacts.encoder_seed(),
            artifacts.handshake_data_decommitment(),
        )
        .unwrap();

    let data = SessionData::new(
        artifacts.handshake_data_decommitment().clone(),
        transcript_tx,
        transcript_rx,
        artifacts.merkle_tree().clone(),
        SubstringsCommitmentSet::new(commitments),
    );
    let session = NotarizedSession::new(header, Some(signature), data);

    // Prover converts NotarizedSession into SessionProof and SubstringsProof and sends them to the Verifier
    let session_proof = session.session_proof();
    let substrings_proof = session.generate_substring_proof([0, 1].to_vec()).unwrap();

    //---------------------------------------
    let session_proof_bytes = bincode::serialize(&session_proof).unwrap();
    let substrings_proof_bytes = bincode::serialize(&substrings_proof).unwrap();
    let session_proof: SessionProof = bincode::deserialize(&session_proof_bytes).unwrap();
    let substrings_proof: SubstringsProof = bincode::deserialize(&substrings_proof_bytes).unwrap();
    //---------------------------------------

    // The Verifier does:
    let SessionProof {
        header,
        signature,
        handshake_data_decommitment,
    } = session_proof;

    // the Verifier checks the header against the Notary's pubkey
    #[allow(irrefutable_let_patterns)]
    let Signature::P256(signature) = signature.unwrap() else {
        panic!("Notary signature is not P256");
    };

    notary_pubkey
        .verify(&header.to_bytes(), &signature)
        .unwrap();

    // verify the decommitment against the commitment which the Notary signed
    handshake_data_decommitment
        .verify(header.handshake_summary().handshake_commitment())
        .unwrap();

    // Verify the handshake data. This checks the server's cert chain, the server's signature,
    // and the provided DNS name
    handshake_data_decommitment
        .data()
        .verify(
            &fixtures::cert::cert_verifier(),
            UNIX_EPOCH + Duration::from_secs(header.handshake_summary().time()),
            &testdata.dns_name,
        )
        .unwrap();

    let (sent_slices, recv_slices) = substrings_proof.verify(&header).unwrap();

    assert_eq!(sent_slices[0].data(), b"se".as_slice());
    assert_eq!(recv_slices[0].data(), b"ec".as_slice());

    assert_eq!(sent_slices[0].range(), &range1);
    assert_eq!(recv_slices[0].range(), &range2);
}
