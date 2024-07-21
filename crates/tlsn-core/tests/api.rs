use std::ops::Range;

use p256::{
    ecdsa::{
        signature::{SignerMut, Verifier},
        Signature as P256Signature, SigningKey,
    },
    PublicKey,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use tls_core::{
    cert::ServerCertDetails,
    handshake::HandshakeData,
    ke::ServerKxDetails,
    msgs::{enums::SignatureScheme, handshake::DigitallySignedStruct},
};

use mpz_core::{commit::HashCommit, serialize::CanonicalSerialize};

use tlsn_core::{
    commitment::TranscriptCommitmentBuilder,
    fixtures,
    msg::SignedSessionHeader,
    proof::{SessionProof, SubstringsProof},
    HandshakeSummary, NotarizedSession, ServerName, SessionData, SessionHeader, Signature,
    Transcript,
};

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
    let encodings_provider = fixtures::encoding_provider(data_sent, data_recv);

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

    let mut commitment_builder =
        TranscriptCommitmentBuilder::new(encodings_provider, data_sent.len(), data_recv.len());

    let commitment_id_1 = commitment_builder.commit_sent(&range1).unwrap();
    let commitment_id_2 = commitment_builder.commit_recv(&range2).unwrap();

    let commitments = commitment_builder.build().unwrap();

    let notarized_session_data = SessionData::new(
        ServerName::Dns(testdata.dns_name.clone()),
        hs_decommitment.clone(),
        transcript_tx,
        transcript_rx,
        commitments,
    );

    // Some outer context generates an (ephemeral) signing key for the Notary, e.g.
    let mut rng = ChaCha20Rng::from_seed([6u8; 32]);
    let signing_key = SigningKey::random(&mut rng);
    let raw_key = signing_key.to_bytes();

    // Notary receives the raw signing key from some outer context
    let mut signer = SigningKey::from_bytes(&raw_key).unwrap();
    let notary_pubkey = PublicKey::from(*signer.verifying_key());
    let notary_verifing_key = *signer.verifying_key();

    // Notary creates the session header
    assert!(data_sent.len() <= (u32::MAX as usize) && data_recv.len() <= (u32::MAX as usize));

    let header = SessionHeader::new(
        fixtures::encoder_seed(),
        notarized_session_data.commitments().merkle_root(),
        data_sent.len(),
        data_recv.len(),
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
        notary_verifing_key
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
            &notarized_session_data.commitments().merkle_root(),
            header.encoder_seed(),
            &notarized_session_data.session_info().handshake_decommitment,
        )
        .unwrap();

    let session = NotarizedSession::new(header, Some(signature), notarized_session_data);

    // Prover converts NotarizedSession into SessionProof and SubstringsProof and sends them to the Verifier
    let session_proof = session.session_proof();

    let mut substrings_proof_builder = session.data().build_substrings_proof();

    substrings_proof_builder
        .reveal_by_id(commitment_id_1)
        .unwrap()
        .reveal_by_id(commitment_id_2)
        .unwrap();

    let substrings_proof = substrings_proof_builder.build().unwrap();

    //---------------------------------------
    let session_proof_bytes = bincode::serialize(&session_proof).unwrap();
    let substrings_proof_bytes = bincode::serialize(&substrings_proof).unwrap();
    let session_proof: SessionProof = bincode::deserialize(&session_proof_bytes).unwrap();
    let substrings_proof: SubstringsProof = bincode::deserialize(&substrings_proof_bytes).unwrap();
    //---------------------------------------

    // The Verifier does:
    session_proof
        .verify_with_default_cert_verifier(notary_pubkey)
        .unwrap();

    let SessionProof {
        header,
        session_info,
        ..
    } = session_proof;

    // assert dns name is expected
    assert_eq!(
        session_info.server_name.as_ref(),
        testdata.dns_name.as_str()
    );

    let (sent, recv) = substrings_proof.verify(&header).unwrap();

    assert_eq!(&sent.data()[range1], b"se".as_slice());
    assert_eq!(&recv.data()[range2], b"ec".as_slice());
}
