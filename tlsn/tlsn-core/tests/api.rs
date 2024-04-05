use std::ops::Range;

use p256::{
    ecdsa::{
        signature::{SignerMut, Verifier},
        Signature as P256Signature, SigningKey,
    },
    PublicKey,
};
use rand::{thread_rng, Rng};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use serde::{Deserialize, Serialize};
use tls_core::cert;
use tlsn_core::{
    attestation::{
        self, Attestation, AttestationBodyBuilder, AttestationFull, AttestationHeader, Field,
        Secret, ATTESTATION_VERSION,
    },
    conn::{
        CertificateSecrets, ConnectionInfo, HandshakeData, HandshakeDataV1_2, ServerIdentityProof,
        TlsVersion,
    },
    encoding::{EncodingCommitment, EncodingTree},
    fixtures::{self, ConnectionFixture},
    hash::HashAlgorithm,
    substring::{SubstringCommitConfigBuilder, SubstringProof, SubstringProofConfigBuilder},
    Signature, Transcript,
};
use tlsn_data_fixtures::http::{request::GET_WITH_HEADER, response::OK_JSON};

#[test]
/// Tests that the attestation protocol and verification work end-to-end
fn test_api() {
    let transcript = Transcript::new(GET_WITH_HEADER, OK_JSON);
    let (sent_len, recv_len) = transcript.len();
    // Plaintext encodings which the Prover obtained from GC evaluation
    let encodings_provider = fixtures::encoding_provider(GET_WITH_HEADER, OK_JSON);

    // At the end of the TLS connection the Prover holds the:
    let ConnectionFixture {
        server_identity,
        connection_info,
        handshake_data,
        certificate_data,
    } = ConnectionFixture::tlsnotary(transcript.length());

    // Prover commits to the certificate data.
    let certificate_secrets = CertificateSecrets {
        data: certificate_data,
        cert_nonce: thread_rng().gen(),
        chain_nonce: thread_rng().gen(),
    };

    let cert_commitment = certificate_secrets
        .cert_commitment(HashAlgorithm::Blake3)
        .unwrap();
    let cert_chain_commiment = certificate_secrets
        .cert_chain_commitment(HashAlgorithm::Blake3)
        .unwrap();

    // Prover specifies the substrings it wants to commit to.
    let mut substrings_commitment_builder = SubstringCommitConfigBuilder::new(&transcript);
    substrings_commitment_builder
        .commit_sent(&(0..sent_len))
        .unwrap()
        .commit_recv(&(0..recv_len))
        .unwrap();

    let substrings_commitment_config = substrings_commitment_builder.build().unwrap();

    // Prover constructs encoding tree.
    let encoding_tree = EncodingTree::new(
        HashAlgorithm::Blake3,
        substrings_commitment_config.iter_encoding(),
        &encodings_provider,
        &transcript.length(),
    )
    .unwrap();

    // Prover sends the encoding root to the Notary.
    let encoding_commitment_root = encoding_tree.root();

    // Notary constructs an attestation body according to their view of the connection.
    let mut builder = AttestationBodyBuilder::default();
    builder
        .field(Field::ConnectionInfo(connection_info))
        .field(Field::HandshakeData(handshake_data))
        .field(Field::CertificateCommitment(cert_commitment))
        .field(Field::CertificateChainCommitment(cert_chain_commiment))
        .field(Field::EncodingCommitment(EncodingCommitment {
            root: encoding_commitment_root,
            seed: fixtures::encoder_seed().to_vec(),
        }));

    let attestation_body = builder.build().unwrap();

    // Some outer context generates an (ephemeral) signing key for the Notary, e.g.
    let mut rng = ChaCha20Rng::from_seed([6u8; 32]);
    let signing_key = SigningKey::random(&mut rng);
    let raw_key = signing_key.to_bytes();

    // Notary receives the raw signing key from some outer context
    let mut signer = SigningKey::from_bytes(&raw_key).unwrap();
    let notary_pubkey = PublicKey::from(*signer.verifying_key());
    let notary_verifing_key = *signer.verifying_key();

    // Notary generates the attestation header and signs it.
    let attestation_header = AttestationHeader {
        id: thread_rng().gen::<[u8; 16]>().into(),
        version: ATTESTATION_VERSION.clone(),
        root: attestation_body.root(HashAlgorithm::Blake3),
    };

    let sig = Signature::P256(signer.sign(&attestation_header.serialize()));

    // Notary optionally logs the attestation.
    _ = Attestation {
        sig: sig.clone(),
        header: attestation_header.clone(),
        body: attestation_body.clone(),
    };

    // Notary sends the attestation header and signature to the Prover.
    #[derive(Serialize, Deserialize)]
    struct SignedHeader {
        header: AttestationHeader,
        signature: Signature,
    }

    //---------------------------------------
    let msg_bytes = bincode::serialize(&SignedHeader {
        header: attestation_header,
        signature: sig,
    })
    .unwrap();
    let SignedHeader { header, signature } = bincode::deserialize(&msg_bytes).unwrap();
    //---------------------------------------

    // Prover locally constructs the expected attestation body according to its view.
    let attestation_body = attestation_body;

    // Prover verifies the attestation root.
    assert_eq!(&attestation_body.root(HashAlgorithm::Blake3), &header.root);

    // Prover verifies the signature.
    #[allow(irrefutable_let_patterns)]
    if let Signature::P256(signature) = signature {
        notary_verifing_key
            .verify(&header.serialize(), &signature)
            .unwrap();
    } else {
        panic!("Notary signature is not P256");
    };

    // Prover stores the attestation.
    let attestation_full = AttestationFull {
        sig: signature,
        header: header,
        body: attestation_body,
        transcript,
        secrets: vec![
            Secret::Certificate(certificate_secrets),
            Secret::ServerIdentity(server_identity),
            Secret::EncodingTree(encoding_tree),
        ],
    };

    // Prover sends the attestation to a Verifier, including server identity proof and substring proofs.
    let attestation = attestation_full.to_attestation();
    let server_identity_proof = attestation_full.identity_proof().unwrap();

    let mut builder = attestation_full.substring_proof_config_builder();
    builder.reveal_sent(&(0..sent_len)).unwrap();
    builder.reveal_recv(&(0..recv_len)).unwrap();

    let config = builder.build().unwrap();

    let substring_proof = attestation_full.substring_proof(&config).unwrap();

    // Test serialization.
    let attestation: Attestation =
        bincode::deserialize(&bincode::serialize(&attestation).unwrap()).unwrap();
    let server_identity_proof: ServerIdentityProof =
        bincode::deserialize(&bincode::serialize(&server_identity_proof).unwrap()).unwrap();
    let substring_proof: SubstringProof =
        bincode::deserialize(&bincode::serialize(&substring_proof).unwrap()).unwrap();

    // Verifier verifies proofs.
    todo!()
}
