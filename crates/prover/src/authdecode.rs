use std::mem;

use crate::error;
use authdecode_core::{
    backend::{
        halo2::{Bn256F, CHUNK_SIZE},
        traits::Field,
    },
    prover::{
        CommitmentData, Committed, Initialized, ProofGenerated, ProverError as CoreProverError,
    },
    Prover as AuthDecodeProver, SSP,
};
use authdecode_single_range::{SingleRange, TranscriptEncoder};
use mpz_core::utils::blake3;
use tlsn_core::{
    hash::HashAlgId,
    request::Request,
    transcript::{
        authdecode::{AuthdecodeInputs, AuthdecodeInputsWithAlg},
        encoding::EncodingProvider,
        Transcript,
    },
    Secrets,
};

/// Returns an AuthDecode prover for a TLS transcript based on the hashing algorithm used in the
/// `request`.
pub(crate) fn authdecode_prover(
    request: &Request,
    secrets: &Secrets,
    encoding_provider: &(dyn EncodingProvider + Send + Sync),
    transcript: &Transcript,
    max_plaintext: usize,
) -> Result<impl TranscriptProver, error::ProverError> {
    let inputs: AuthdecodeInputsWithAlg = (request, secrets, encoding_provider, transcript)
        .try_into()
        .map_err(error::ProverError::authdecode)?;

    if inputs.total_plaintext() > max_plaintext {
        return Err(error::ProverError::authdecode(
            "total plaintext length exceeds the maximum allowed",
        ));
    }

    match inputs.alg {
        HashAlgId::POSEIDON_HALO2 => Ok(PoseidonHalo2Prover::new(inputs.inputs)),
        alg => Err(error::ProverError::authdecode(format!(
            "unsupported hash algorithm {:?} for AuthDecode",
            alg
        ))),
    }
}

/// An AuthDecode prover for a TLS transcript.
pub(crate) trait TranscriptProver {
    /// Creates a new prover instantiated with the given `inputs`.
    ///
    /// # Panics
    ///
    /// Panics if the `inputs` are malformed.
    fn new(inputs: AuthdecodeInputs) -> Self;

    /// Commits to the commitment data which the prover was instantiated with.
    ///
    /// Returns a message to be passed to the verifier.
    fn commit(&mut self) -> Result<impl serio::Serialize, TranscriptProverError>;

    /// Creates proofs using the `seed` to generate encodings.
    ///
    /// Returns a message to be passed to the verifier.
    fn prove(&mut self, seed: [u8; 32]) -> Result<impl serio::Serialize, TranscriptProverError>;
}

/// An AuthDecode prover for a batch of data from a TLS transcript using the
/// POSEIDON_HALO2 hash algorithm.
pub(crate) struct PoseidonHalo2Prover {
    /// A batch of AuthDecode commitment data with the plaintext salt.
    commitment_data: Option<Vec<(CommitmentData<SingleRange>, Bn256F)>>,
    /// The prover in the [Initialized] state.
    initialized: Option<AuthDecodeProver<SingleRange, Initialized, Bn256F>>,
    /// The prover in the [Committed] state.
    committed: Option<AuthDecodeProver<SingleRange, Committed<SingleRange, Bn256F>, Bn256F>>,
    /// The prover in the [ProofGenerated] state.
    proof_generated:
        Option<AuthDecodeProver<SingleRange, ProofGenerated<SingleRange, Bn256F>, Bn256F>>,
}

impl TranscriptProver for PoseidonHalo2Prover {
    fn new(inputs: AuthdecodeInputs) -> Self {
        let inputs = inputs.to_inner();

        for input in &inputs {
            assert!(input.range.len() <= CHUNK_SIZE);
        }
        assert!(!inputs.is_empty());
        // All encodings must have at least SSP bitlength.
        assert!(inputs[0].encodings[0].len() * 8 >= SSP);

        let commitment_data = inputs
            .into_iter()
            .map(|input| {
                // Hash the encodings to break the correlation and truncate them.
                let hashed_encodings = input
                    .encodings
                    .into_iter()
                    .map(|enc| {
                        let mut enc_new = [0u8; SSP / 8];
                        enc_new.copy_from_slice(&blake3(&enc)[0..SSP / 8]);
                        enc_new
                    })
                    .collect::<Vec<_>>();

                (
                    CommitmentData::new(
                        &input.plaintext,
                        &hashed_encodings,
                        SingleRange::new(input.direction, &input.range),
                    ),
                    Bn256F::from_bytes_be(input.salt.to_vec()),
                )
            })
            .collect::<Vec<_>>();

        Self {
            initialized: Some(AuthDecodeProver::new(Box::new(
                authdecode_core::backend::halo2::prover::Prover::new(),
            ))),
            committed: None,
            proof_generated: None,
            commitment_data: Some(commitment_data),
        }
    }

    fn commit(&mut self) -> Result<impl serio::Serialize, TranscriptProverError> {
        let prover = mem::take(&mut self.initialized).ok_or(TranscriptProverError::Other(
            "The prover was called in the wrong state".to_string(),
        ))?;
        let commitment = mem::take(&mut self.commitment_data)
            .ok_or(TranscriptProverError::Other(
                "The commitment data was not set".to_string(),
            ))?
            .into_iter()
            .map(|(comm_data, salt)| (comm_data, vec![salt]))
            .collect::<Vec<_>>();

        let (prover, msg) = prover.commit_with_salt(commitment)?;

        self.committed = Some(prover);
        Ok(msg)
    }

    fn prove(&mut self, seed: [u8; 32]) -> Result<impl serio::Serialize, TranscriptProverError> {
        let encoding_provider = TranscriptEncoder::new(seed);

        let prover = mem::take(&mut self.committed).ok_or(TranscriptProverError::Other(
            "The prover was called in the wrong state".to_string(),
        ))?;

        let (prover, msg) = prover.prove(&encoding_provider)?;
        self.proof_generated = Some(prover);

        Ok(msg)
    }
}

#[derive(Debug, thiserror::Error)]
/// Error for [TranscriptProver].
pub(crate) enum TranscriptProverError {
    #[error(transparent)]
    CoreProtocolError(#[from] CoreProverError),
    #[error("AuthDecode prover failed with an error: {0}")]
    Other(String),
}
