use std::{mem, ops::Range};

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
use authdecode_transcript::{TranscriptData, TranscriptEncoder};
use mpz_core::utils::blake3;
use tlsn_core::{
    hash::{Blinder, HashAlgId},
    transcript::{encoding::EncodingProvider, Direction, Idx, Transcript},
};
use utils::range::RangeSet;

use crate::{error, ProverError};

/// Returns an AuthDecode prover for a TLS transcript based on the hashing algorithm used.
pub(crate) fn authdecode_prover(
    inputs: Vec<(Direction, Range<usize>, HashAlgId, Blinder)>,
    encoding_provider: &(dyn EncodingProvider + Send + Sync),
    transcript: &Transcript,
    max_plaintext: usize,
) -> Result<impl TranscriptProver, error::ProverError> {
    if inputs.is_empty() {
        return Err(ProverError::authdecode("inputs vector is empty"));
    }

    let alg = inputs.first().expect("At least one input is expected").2;

    let mut total_plaitext = 0;

    let adinputs = inputs
        .iter()
        .map(|(dir, range, this_alg, blinder)| {
            if &alg != this_alg {
                return Err(ProverError::authdecode(
                    "more than one hash algorithms are present",
                ));
            }

            total_plaitext += range.len();
            if total_plaitext > max_plaintext {
                return Err(ProverError::authdecode("max_plaintext exceeded"));
            }

            let idx = Idx::new(RangeSet::new(&[range.clone()]));

            let mut encodings = encoding_provider.provide_bit_encodings(*dir, &idx).ok_or(
                ProverError::authdecode(format!(
                    "direction {} and index {:?} were not found by the encoding provider",
                    &dir, &idx
                )),
            )?;
            // Reverse byte encodings to MSB0.
            for chunk in encodings.chunks_mut(8) {
                chunk.reverse();
            }

            let plaintext = transcript
                .get(*dir, &idx)
                .ok_or(ProverError::authdecode(format!(
                    "direction {} and index {:?} were not found in the transcript",
                    &dir, &idx
                )))?
                .data()
                .to_vec();

            Ok(AuthDecodeInput::new(
                blinder.clone(),
                plaintext,
                encodings,
                range.clone(),
                *dir,
            ))
        })
        .collect::<Result<Vec<_>, ProverError>>()?;

    match alg {
        HashAlgId::POSEIDON_BN256_434 => Ok(PoseidonHalo2Prover::new(AuthdecodeInputs(adinputs))),
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

    /// Returns the hash algorithm used to create commitments.
    fn alg(&self) -> HashAlgId;
}

/// An AuthDecode prover for a batch of data from a TLS transcript using the
/// POSEIDON_HALO2 hash algorithm.
pub(crate) struct PoseidonHalo2Prover {
    /// A batch of AuthDecode commitment data with the plaintext salt.
    commitment_data: Option<Vec<(CommitmentData<TranscriptData>, Bn256F)>>,
    /// The prover in the [Initialized] state.
    initialized: Option<AuthDecodeProver<TranscriptData, Initialized, Bn256F>>,
    /// The prover in the [Committed] state.
    committed: Option<AuthDecodeProver<TranscriptData, Committed<TranscriptData, Bn256F>, Bn256F>>,
    /// The prover in the [ProofGenerated] state.
    proof_generated:
        Option<AuthDecodeProver<TranscriptData, ProofGenerated<TranscriptData, Bn256F>, Bn256F>>,
}

impl TranscriptProver for PoseidonHalo2Prover {
    fn new(inputs: AuthdecodeInputs) -> Self {
        let inputs = inputs.into_inner();

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
                        TranscriptData::new(input.direction, &input.range),
                    ),
                    Bn256F::from_bytes_be(input.salt.as_inner().to_vec()),
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

    fn alg(&self) -> HashAlgId {
        HashAlgId::POSEIDON_BN256_434
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

/// An AuthDecode input to prove a single range of a TLS transcript. Also contains the `salt` to be
/// used for the plaintext commitment.
struct AuthDecodeInput {
    /// The salt of the plaintext commitment.
    pub salt: Blinder,
    /// The plaintext to commit to.
    pub plaintext: Vec<u8>,
    /// The encodings to commit to in MSB0 bit order.
    pub encodings: Vec<Vec<u8>>,
    /// The byterange of the plaintext.
    pub range: Range<usize>,
    /// The direction of the range in the transcript.
    pub direction: Direction,
}

impl AuthDecodeInput {
    /// Creates a new `AuthDecodeInput`.
    ///
    /// # Panics
    ///
    /// Panics if some of the arguments are not correct.
    fn new(
        salt: Blinder,
        plaintext: Vec<u8>,
        encodings: Vec<Vec<u8>>,
        range: Range<usize>,
        direction: Direction,
    ) -> Self {
        assert!(!range.is_empty());
        assert!(plaintext.len() * 8 == encodings.len());
        assert!(plaintext.len() == range.len());
        // All encodings should have the same length.
        for pair in encodings.windows(2) {
            assert!(pair[0].len() == pair[1].len());
        }
        Self {
            salt,
            plaintext,
            encodings,
            range,
            direction,
        }
    }
}

/// A batch of AuthDecode inputs.  
pub(crate) struct AuthdecodeInputs(Vec<AuthDecodeInput>);

impl AuthdecodeInputs {
    /// Consumes self, returning the inner vector.
    fn into_inner(self) -> Vec<AuthDecodeInput> {
        self.0
    }
}
