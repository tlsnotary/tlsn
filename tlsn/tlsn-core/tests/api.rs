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
    msg::SignedSessionHeader, signature::Signature, substrings::SubstringsProof,
    transcript::get_encoding_ids, Direction, HandshakeSummary, NotarizedSession,
    SessionDataBuilder, SessionHeader, SessionProof, Transcript,
};

use tlsn_fixtures as fixtures;

#[test]
/// Tests that the commitment creation protocol and verification work end-to-end
fn test_api() {
    let testdata = fixtures::cert::tlsnotary();
    // Prover's transcript
    let data_sent = "sent data".as_bytes();
    let data_recv = "received data".as_bytes();
    let transcript_tx = Transcript::new(data_sent.to_vec());
    let transcript_rx = Transcript::new(data_recv.to_vec());

    // Ranges of plaintext for which the Prover wants to create a commitment
    let range1: Range<usize> = Range { start: 0, end: 2 };
    let range2: Range<usize> = Range { start: 1, end: 3 };

    // Plaintext encodings which the Prover obtained from GC evaluation
    // (for simplicity of this test we instead generate the encodings using the Notary's encoder)
    let notary_encoder_seed = [5u8; 32];
    let notary_encoder = ChaChaEncoder::new(notary_encoder_seed);

    // active encodings for each byte in range1
    let active_encodings_range1: Vec<EncodedValue<_>> =
        get_encoding_ids(&range1.clone().into(), Direction::Sent)
            .map(|id| notary_encoder.encode_by_type(ValueId::new(&id).to_u64(), &ValueType::U8))
            .zip(transcript_tx.data()[range1.clone()].to_vec())
            .map(|(enc, value)| enc.select(value).unwrap())
            .collect();

    // Full encodings for each byte in range2
    let active_encodings_range2: Vec<EncodedValue<_>> =
        get_encoding_ids(&range2.clone().into(), Direction::Received)
            .map(|id| notary_encoder.encode_by_type(ValueId::new(&id).to_u64(), &ValueType::U8))
            .zip(transcript_rx.data()[range2.clone()].to_vec())
            .map(|(enc, value)| enc.select(value).unwrap())
            .collect();

    // At the end of the session the Prover holds the:
    // - time when the TLS handshake began
    // - server ephemeral key
    // - handshake data (to which the Prover sent a commitment earlier)
    // - encoder seed revealed by the Notary at the end of the label commitment protocol

    let time = testdata.time;
    let ephem_key = testdata.pubkey.clone();

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

    let mut session_data_builder =
        SessionDataBuilder::new(hs_decommitment.clone(), transcript_tx, transcript_rx);

    let commitment_id_1 = session_data_builder
        .add_substrings_commitment(
            range1.clone().into(),
            Direction::Sent,
            &active_encodings_range1,
        )
        .unwrap();
    let commitment_id_2 = session_data_builder
        .add_substrings_commitment(
            range2.clone().into(),
            Direction::Received,
            &active_encodings_range2,
        )
        .unwrap();

    let session_data = session_data_builder.build().unwrap();

    // Some outer context generates an (ephemeral) signing key for the Notary, e.g.
    let mut rng = ChaCha20Rng::from_seed([6u8; 32]);
    let signing_key = SigningKey::random(&mut rng);
    let raw_key = signing_key.to_bytes();

    // Notary receives the raw signing key from some outer context
    let mut signer = SigningKey::from_bytes(&raw_key).unwrap();
    let notary_pubkey = *signer.verifying_key();

    // Notary creates the session header
    assert!(data_sent.len() <= (u32::MAX as usize) && data_recv.len() <= (u32::MAX as usize));

    let header = SessionHeader::new(
        notary_encoder_seed,
        session_data.merkle_tree().root(),
        data_sent.len() as u32,
        data_recv.len() as u32,
        // the session's end time and TLS handshake start time may be a few mins apart
        HandshakeSummary::new(time + 60, ephem_key.clone(), hs_commitment),
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
            time,
            &ephem_key,
            &session_data.merkle_tree().root(),
            header.encoder_seed(),
            session_data.handshake_data_decommitment(),
        )
        .unwrap();

    let session = NotarizedSession::new(header, Some(signature), session_data);

    // Prover converts NotarizedSession into SessionProof and SubstringsProof and sends them to the Verifier
    let session_proof = session.session_proof();

    let mut substrings_proof_builder = session.data().build_substrings_proof();

    substrings_proof_builder
        .reveal(commitment_id_1)
        .unwrap()
        .reveal(commitment_id_2)
        .unwrap();

    let substrings_proof = substrings_proof_builder.build().unwrap();

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

    assert_eq!(sent_slices[0].range(), range1);
    assert_eq!(recv_slices[0].range(), range2);
}
