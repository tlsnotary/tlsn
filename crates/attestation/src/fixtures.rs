//! Attestation fixtures.
use tlsn_core::{
    connection::{CertBinding, CertBindingV1_2},
    fixtures::ConnectionFixture,
    hash::HashAlgorithm,
    transcript::{Transcript, TranscriptCommitConfigBuilder, TranscriptCommitment},
};

use crate::{
    Attestation, AttestationConfig, CryptoProvider, Extension,
    request::{Request, RequestConfig},
    signing::{
        KeyAlgId, SignatureAlgId, SignatureVerifier, SignatureVerifierProvider, Signer,
        SignerProvider,
    },
};

/// A Request fixture used for testing.
#[allow(missing_docs)]
pub struct RequestFixture {
    pub request: Request,
}

/// Returns a request fixture for testing.
pub fn request_fixture(
    transcript: Transcript,
    connection: ConnectionFixture,
    _hasher: impl HashAlgorithm,
    extensions: Vec<Extension>,
) -> RequestFixture {
    let provider = CryptoProvider::default();
    let (sent_len, recv_len) = transcript.len();

    let ConnectionFixture {
        server_name,
        server_cert_data,
        ..
    } = connection;

    let mut transcript_commitment_builder = TranscriptCommitConfigBuilder::new(&transcript);
    transcript_commitment_builder
        .commit_sent(&(0..sent_len))
        .unwrap()
        .commit_recv(&(0..recv_len))
        .unwrap();
    let transcripts_commitment_config = transcript_commitment_builder.build().unwrap();

    let mut builder = RequestConfig::builder();

    builder.transcript_commit(transcripts_commitment_config);

    for extension in extensions {
        builder.extension(extension);
    }

    let request_config = builder.build().unwrap();

    let mut request_builder = Request::builder(&request_config);
    request_builder
        .server_name(server_name)
        .handshake_data(server_cert_data)
        .transcript(transcript);

    let (request, _) = request_builder.build(&provider).unwrap();

    RequestFixture { request }
}

/// Returns an attestation fixture for testing.
pub fn attestation_fixture(
    request: Request,
    connection: ConnectionFixture,
    signature_alg: SignatureAlgId,
    transcript_commitments: &[TranscriptCommitment],
) -> Attestation {
    let ConnectionFixture {
        connection_info,
        server_cert_data,
        ..
    } = connection;

    let CertBinding::V1_2(CertBindingV1_2 {
        server_ephemeral_key,
        ..
    }) = server_cert_data.binding
    else {
        panic!("expected v1.2 binding data");
    };

    let mut provider = CryptoProvider::default();
    match signature_alg {
        SignatureAlgId::SECP256K1 => provider.signer.set_secp256k1(&[42u8; 32]).unwrap(),
        SignatureAlgId::SECP256K1ETH => provider.signer.set_secp256k1eth(&[43u8; 32]).unwrap(),
        SignatureAlgId::SECP256R1 => provider.signer.set_secp256r1(&[44u8; 32]).unwrap(),
        _ => unimplemented!(),
    };

    let attestation_config = AttestationConfig::builder()
        .supported_signature_algs([signature_alg])
        .build()
        .unwrap();

    let mut attestation_builder = Attestation::builder(&attestation_config)
        .accept_request(request)
        .unwrap();

    attestation_builder
        .connection_info(connection_info)
        .server_ephemeral_key(server_ephemeral_key)
        .transcript_commitments(transcript_commitments.to_vec());

    attestation_builder.build(&provider).unwrap()
}

/// Returns a crypto provider which supports only a custom signature alg.
pub fn custom_provider_fixture() -> CryptoProvider {
    const CUSTOM_SIG_ALG_ID: SignatureAlgId = SignatureAlgId::new(128);

    // A dummy signer.
    struct DummySigner {}
    impl Signer for DummySigner {
        fn alg_id(&self) -> SignatureAlgId {
            CUSTOM_SIG_ALG_ID
        }

        fn sign(
            &self,
            msg: &[u8],
        ) -> Result<crate::signing::Signature, crate::signing::SignatureError> {
            Ok(crate::signing::Signature {
                alg: CUSTOM_SIG_ALG_ID,
                data: msg.to_vec(),
            })
        }

        fn verifying_key(&self) -> crate::signing::VerifyingKey {
            crate::signing::VerifyingKey {
                alg: KeyAlgId::new(128),
                data: vec![1, 2, 3, 4],
            }
        }
    }

    // A dummy verifier.
    struct DummyVerifier {}
    impl SignatureVerifier for DummyVerifier {
        fn alg_id(&self) -> SignatureAlgId {
            CUSTOM_SIG_ALG_ID
        }

        fn verify(
            &self,
            _key: &crate::signing::VerifyingKey,
            msg: &[u8],
            sig: &[u8],
        ) -> Result<(), crate::signing::SignatureError> {
            if msg == sig {
                Ok(())
            } else {
                Err(crate::signing::SignatureError::from_str(
                    "invalid signature",
                ))
            }
        }
    }

    let mut provider = CryptoProvider::default();

    let mut signer_provider = SignerProvider::default();
    signer_provider.set_signer(Box::new(DummySigner {}));
    provider.signer = signer_provider;

    let mut verifier_provider = SignatureVerifierProvider::empty();
    verifier_provider.set_verifier(Box::new(DummyVerifier {}));
    provider.signature = verifier_provider;

    provider
}
