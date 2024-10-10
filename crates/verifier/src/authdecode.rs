use std::mem;

use authdecode_core::{
    backend::{
        halo2::{Bn256F, CHUNK_SIZE},
        traits::Field,
    },
    msgs::{Commit, Proofs},
    verifier::{CommitmentReceived, Initialized, Verifier, VerifierError as CoreVerifierError},
};
use authdecode_single_range::{SingleRange, TranscriptEncoder};
use tlsn_core::{
    hash::{HashAlgId, TypedHash},
    request::Request,
    transcript::{authdecode::AuthDecodeAlg, Idx, PlaintextHash},
};

/// Returns an AuthDecode verifier depending on the hash algorithm contained in the request.
pub(crate) fn authdecode_verifier(request: &Request) -> impl TranscriptVerifier {
    let alg: AuthDecodeAlg = request.try_into().unwrap();

    match alg.alg() {
        &HashAlgId::POSEIDON_HALO2 => PoseidonHalo2Verifier::new(),
        _ => unimplemented!(),
    }
}

/// An AuthDecode verifier for a TLS transcript.
pub(crate) trait TranscriptVerifier {
    type CommitmentMessage: serio::Deserialize;
    type ProofMessage: serio::Deserialize;

    /// Creates a new verifier.
    fn new() -> Self;

    /// Receives commitments.
    ///
    /// # Arguments
    ///
    /// * `commitments` - The commitments to receive.
    /// * `max_plaintext` - The maximum bytesize of committed plaintext allowed to be contained in the
    ///                     `commitments`.
    fn receive_commitments(
        &mut self,
        commitments: Self::CommitmentMessage,
        max_plaintext: usize,
    ) -> Result<(), TranscriptVerifierError>;

    /// Verifies proofs and returns authenticated plaintext hashes.
    ///
    /// # Arguments
    ///
    /// * `proofs` - The proofs to verify.
    /// * `seed` - The seed to generate encodings from.
    fn verify(
        &mut self,
        proofs: Self::ProofMessage,
        seed: [u8; 32],
    ) -> Result<Vec<PlaintextHash>, TranscriptVerifierError>;
}

/// An AuthDecode verifier which uses hashes of the POSEIDON_HALO2 kind.
pub(crate) struct PoseidonHalo2Verifier {
    /// The verifier in the [Initialized] state.
    initialized: Option<Verifier<SingleRange, Initialized, Bn256F>>,
    /// The verifier in the [CommitmentReceived] state.
    commitment_received:
        Option<Verifier<SingleRange, CommitmentReceived<SingleRange, Bn256F>, Bn256F>>,
}

impl TranscriptVerifier for PoseidonHalo2Verifier {
    type CommitmentMessage = Commit<SingleRange, Bn256F>;
    type ProofMessage = Proofs;

    fn new() -> Self {
        Self {
            initialized: Some(Verifier::new(Box::new(
                authdecode_core::backend::halo2::verifier::Verifier::new(),
            ))),
            commitment_received: None,
        }
    }

    fn receive_commitments(
        &mut self,
        commitments: Self::CommitmentMessage,
        max_plaintext: usize,
    ) -> Result<(), TranscriptVerifierError> {
        let verifier = mem::take(&mut self.initialized).ok_or(TranscriptVerifierError::Other(
            "The verifier was called in the wrong state".to_string(),
        ))?;

        if commitments.commitment_count() != commitments.chunk_count() {
            return Err(TranscriptVerifierError::Other(
                "Some commitments contain more than one chunk of plaintext data".to_string(),
            ));
        }

        if commitments.chunk_count() * CHUNK_SIZE > max_plaintext {
            return Err(TranscriptVerifierError::Other(
                "The amount of data in commitments exceeded the limit".to_string(),
            ));
        }

        self.commitment_received = Some(verifier.receive_commitments(commitments)?);

        Ok(())
    }

    fn verify(
        &mut self,
        proofs: Self::ProofMessage,
        seed: [u8; 32],
    ) -> Result<Vec<PlaintextHash>, TranscriptVerifierError> {
        let verifier =
            mem::take(&mut self.commitment_received).ok_or(TranscriptVerifierError::Other(
                "The verifier was called in the wrong state".to_string(),
            ))?;

        let encoding_provider = TranscriptEncoder::new(seed);

        let verifier = verifier.verify(proofs, &encoding_provider)?;

        let coms = verifier
            .commitments()
            .iter()
            .map(|com| {
                // Earlier we checked that each commitment has only one chunk.
                debug_assert!(com.chunk_commitments().len() == 1);

                let com = &com.chunk_commitments()[0];
                let range = com.ids();
                PlaintextHash {
                    direction: *range.direction(),
                    hash: TypedHash {
                        alg: HashAlgId::POSEIDON_HALO2,
                        value: com
                            .plaintext_hash()
                            .clone()
                            .to_bytes_be()
                            .try_into()
                            .unwrap(),
                    },
                    idx: Idx::new(range.range().clone()),
                }
            })
            .collect();

        Ok(coms)
    }
}

#[derive(Debug, thiserror::Error)]
/// Error for [TranscriptVerifier].
pub(crate) enum TranscriptVerifierError {
    #[error(transparent)]
    CoreProtocolError(#[from] CoreVerifierError),
    #[error("AuthDecode verifier failed with an error: {0}")]
    Other(String),
}
