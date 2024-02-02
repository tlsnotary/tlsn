use crate::{
    encodings::{ActiveEncodings, FullEncodings},
    prover::{backend::Backend, error, error::ProverError, state},
    utils::u8vec_to_boolvec,
    Delta,
};

use mpz_core::utils::blake3;
use num::{BigInt, BigUint};

use super::{EncodingVerifier, VerificationData};
use crate::encodings::ToActiveEncodings;

/// Details pertaining to an AuthDecode commitment to a single chunk of the plaintext.
#[derive(Clone)]
pub struct ChunkCommitmentDetails {
    /// The chunk of plaintext to commit to.
    pub plaintext: Vec<bool>,
    pub plaintext_hash: BigUint,
    pub plaintext_salt: BigUint,

    // The converted (i.e. uncorrelated and truncated) encodings to commit to.
    pub encodings: ActiveEncodings,
    pub encoding_sum: BigUint,
    pub encoding_sum_hash: BigUint,
    pub encoding_sum_salt: BigUint,
}

/// Details pertaining to an AuthDecode commitment to plaintext of arbitrary length.
#[derive(Clone, Default)]
pub struct CommitmentDetails {
    /// Details pertaining to commitments to each chunk of the plaintext.
    pub chunk_commitments: Vec<ChunkCommitmentDetails>,
}

impl CommitmentDetails {
    /// Returns the plaintext of this commitment.
    pub fn plaintext(&self) -> Vec<bool> {
        self.chunk_commitments
            .iter()
            .map(|com| com.plaintext.clone())
            .flatten()
            .collect()
    }

    /// Returns the encodings of the plaintext of this commitment.
    pub fn encodings(&self) -> ActiveEncodings {
        let mut active = ActiveEncodings::default();
        for chunk in self.chunk_commitments.clone() {
            active.extend(chunk.encodings);
        }
        active
    }
}

// Public and private inputs to the zk circuit
#[derive(Clone, Default)]
pub struct ProofInput {
    // Public
    pub plaintext_hash: BigUint,
    pub encoding_sum_hash: BigUint,
    /// The sum of encodings which encode the 0 bit.
    pub zero_sum: BigUint,
    pub deltas: Vec<Delta>,

    // Private
    pub plaintext: Vec<bool>,
    pub plaintext_salt: BigUint,
    pub encoding_sum_salt: BigUint,
}

/// Prover in the AuthDecode protocol.
pub struct Prover<T: state::ProverState> {
    backend: Box<dyn Backend>,
    pub state: T,
}

impl Prover<state::Initialized> {
    /// Creates a new prover.
    pub fn new(backend: Box<dyn Backend>) -> Self {
        Prover {
            backend,
            state: state::Initialized {},
        }
    }

    /// Creates a commitment to each (`plaintext`, `encodings` of the `plaintext` bits) tuple.
    pub fn commit(
        self,
        plaintext_and_encodings: Vec<(Vec<u8>, ActiveEncodings)>,
    ) -> Result<(Prover<state::Committed>, Vec<CommitmentDetails>), ProverError> {
        let commitments = plaintext_and_encodings
            .iter()
            .map(|(plaintext, encodings)| {
                if plaintext.is_empty() {
                    return Err(ProverError::EmptyPlaintext);
                }

                let plaintext = u8vec_to_boolvec(plaintext);

                if plaintext.len() != encodings.len() {
                    return Err(ProverError::Mismatch);
                }

                // Chunk up the plaintext and encodings and commit to them.
                let chunk_commitments = plaintext
                    .chunks(self.backend.chunk_size())
                    .zip(encodings.clone().into_chunks(self.backend.chunk_size()))
                    .map(|(plaintext, encodings)| {
                        // Convert the encodings and compute their sum.
                        let encodings = encodings.convert(plaintext);
                        let sum = encodings.compute_encoding_sum();

                        let (plaintext_hash, plaintext_salt) =
                            self.backend.commit_plaintext(plaintext.to_vec())?;

                        let (encoding_sum_hash, encoding_sum_salt) =
                            self.backend.commit_encoding_sum(sum.clone())?;

                        Ok(ChunkCommitmentDetails {
                            plaintext: plaintext.to_vec(),
                            plaintext_hash,
                            plaintext_salt,
                            encodings,
                            encoding_sum: sum,
                            encoding_sum_hash,
                            encoding_sum_salt,
                        })
                    })
                    .collect::<Result<Vec<ChunkCommitmentDetails>, ProverError>>()?;
                Ok(CommitmentDetails { chunk_commitments })
            })
            .collect::<Result<Vec<CommitmentDetails>, ProverError>>()?;

        Ok((
            Prover {
                backend: self.backend,
                state: state::Committed {
                    commitments: commitments.clone(),
                },
            },
            // TODO we need to convert into a form which can be publicly revealed
            commitments,
        ))
    }
}

impl Prover<state::Committed> {
    /// Checks the authenticity of the peer's encodings used to create commitments.
    ///
    /// The verifier encodings must be in the same order in which the commitments were made.
    pub fn check(
        self,
        // TODO: the verifier should only pass init data
        verification_data: VerificationData,
        verifier: impl EncodingVerifier,
    ) -> Result<Prover<state::Checked>, ProverError> {
        if verification_data.full_encodings_sets.len() != self.state.commitments.len() {
            // TODO proper error
            return Err(ProverError::InternalError);
        }

        verifier.init(verification_data.init_data);

        // Verify encodings of each commitment.
        let verified_encodings = self
            .state
            .commitments
            .iter()
            .zip(verification_data.full_encodings_sets.iter())
            .map(|(com, full_encodings)| {
                verifier.verify(full_encodings)?;

                if com.encodings().len() != full_encodings.len() {
                    // TODO proper error
                    return Err(ProverError::InternalError);
                }
                // Get active converted encodings.
                let active_converted = full_encodings
                    .encode(&com.plaintext())
                    .convert(&com.plaintext());

                if active_converted != com.encodings() {
                    // TODO proper error
                    return Err(ProverError::InternalError);
                }
                Ok(full_encodings.clone().convert())
            })
            .collect::<Result<Vec<FullEncodings>, ProverError>>()?;

        Ok(Prover {
            backend: self.backend,
            state: state::Checked {
                commitments: self.state.commitments,
                full_encodings_sets: verified_encodings,
            },
        })
    }
}

impl Prover<state::Checked> {
    /// Generates a zk proof(s).
    pub fn prove(self) -> Result<(Prover<state::ProofCreated>, Vec<Vec<u8>>), ProverError> {
        let commitments = self.state.commitments.clone();
        let mut sets = self.state.full_encodings_sets.clone();

        // Collect proof inputs to prove each chunk of plaintext committed to.
        let all_inputs = commitments
            .iter()
            .zip(sets.iter())
            .flat_map(|(com, set)| {
                let mut set = set.clone();
                com.chunk_commitments
                    .iter()
                    .map(|com| {
                        let (split, remaining) = set.split_at(com.plaintext.len());
                        set = remaining;

                        ProofInput {
                            deltas: split.compute_deltas(),
                            plaintext_hash: com.plaintext_hash.clone(),
                            encoding_sum_hash: com.encoding_sum_hash.clone(),
                            zero_sum: split.compute_zero_sum(),
                            plaintext: com.plaintext.clone(),
                            plaintext_salt: com.plaintext_salt.clone(),
                            encoding_sum_salt: com.encoding_sum_salt.clone(),
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        let proofs = self.backend.prove(all_inputs)?;

        Ok((
            Prover {
                backend: self.backend,
                state: state::ProofCreated {
                    commitments,
                    proofs: proofs.clone(),
                },
            },
            proofs,
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        prover::{
            backend::Backend as ProverBackend,
            error::ProverError,
            prover::{ProofInput, Prover},
        },
        Proof,
    };
    use num::BigUint;

    /// The prover who implements `Prove` with the correct values
    struct CorrectTestProver {}
    impl ProverBackend for CorrectTestProver {
        fn prove(&self, _: Vec<ProofInput>) -> Result<Vec<Proof>, ProverError> {
            Ok(vec![Proof::default()])
        }

        fn chunk_size(&self) -> usize {
            3670
        }

        fn commit_plaintext(
            &self,
            plaintext: Vec<bool>,
        ) -> Result<(BigUint, BigUint), ProverError> {
            Ok((BigUint::default(), BigUint::default()))
        }

        fn commit_encoding_sum(
            &self,
            encoding_sum: BigUint,
        ) -> Result<(BigUint, BigUint), ProverError> {
            Ok((BigUint::default(), BigUint::default()))
        }
    }

    // #[test]
    // /// Inputs empty plaintext and triggers [ProverError::EmptyPlaintext]
    // fn test_error_empty_plaintext() {
    //     let lsp = Prover::new(Box::new(CorrectTestProver {}));

    //     let pt: Vec<u8> = Vec::new();
    //     let res = lsp.commit(vec![(pt, vec![1u128])]);
    //     assert_eq!(res.err().unwrap(), ProverError::EmptyPlaintext);
    // }
}
