use crate::{
    backend::traits::{Field, ProverBackend as Backend},
    encodings::EncodingProvider,
    id::IdSet,
    msgs::{Commit, Proofs},
    prover::{error::ProverError, state},
};

use super::commitment::{CommitmentData, CommitmentDetails};
use std::{marker::PhantomData, ops::Add};

/// Public and private inputs to the circuit.
#[derive(Clone, Default)]
pub struct ProofInput<F> {
    // Public:
    /// The hash commitment to the plaintext.
    pub plaintext_hash: F,
    /// The hash commitment to the sum of the encodings.
    pub encoding_sum_hash: F,
    /// The sum of encodings which encode the 0 bit.
    pub zero_sum: F,
    /// An arithmetic difference between the encoding of bit value 1 and encoding of bit value 0 for
    /// each bit of the plaintext.
    pub deltas: Vec<F>,

    // Private:
    /// The plaintext committed to.
    pub plaintext: Vec<u8>,
    /// The salt used to create the commitment to the plaintext.
    pub plaintext_salt: F,
    /// The salt used to create the commitment to the sum of the encodings.
    pub encoding_sum_salt: F,
}

/// Prover in the AuthDecode protocol.
pub struct Prover<T: IdSet, S: state::ProverState, F: Field> {
    backend: Box<dyn Backend<F>>,
    pub state: S,
    pd: PhantomData<T>,
}

impl<T, F> Prover<T, state::Initialized, F>
where
    T: IdSet,
    F: Field + Add<Output = F>,
{
    /// Creates a new prover.
    pub fn new(backend: Box<dyn Backend<F>>) -> Self {
        Prover {
            backend,
            state: state::Initialized {},
            pd: PhantomData,
        }
    }

    /// Creates a commitment to each element in the `data_set`.
    #[allow(clippy::type_complexity)]
    pub fn commit(
        self,
        data_set: &[CommitmentData<T>],
    ) -> Result<(Prover<T, state::Committed<T, F>, F>, Commit<T, F>), ProverError>
    where
        T: IdSet,
        F: Field + Clone + std::ops::Add<Output = F>,
    {
        // Commit to each commitment data in the set individually.
        let commitments = data_set
            .iter()
            .map(|data| data.commit(&self.backend))
            .collect::<Result<Vec<CommitmentDetails<T, F>>, ProverError>>()?;

        Ok((
            Prover {
                backend: self.backend,
                state: state::Committed {
                    commitments: commitments.clone(),
                },
                pd: PhantomData,
            },
            commitments.into(),
        ))
    }
}

impl<T, F> Prover<T, state::Committed<T, F>, F>
where
    T: IdSet,
    F: Field + Clone + std::ops::Sub<Output = F> + std::ops::Add<Output = F>,
{
    /// Generates zk proofs.
    #[allow(clippy::type_complexity)]
    pub fn prove(
        self,
        encoding_provider: impl EncodingProvider<T>,
    ) -> Result<(Prover<T, state::ProofGenerated<T, F>, F>, Proofs), ProverError> {
        // Collect proof inputs for each chunk of plaintext committed to.
        let proof_inputs = self
            .state
            .commitments
            .iter()
            .flat_map(|com| {
                let coms = com
                    .chunk_commitments
                    .iter()
                    .map(|com| {
                        let encodings = encoding_provider.get_by_ids(com.ids())?;

                        Ok(ProofInput {
                            deltas: encodings.compute_deltas::<F>(),
                            plaintext_hash: com.plaintext_hash.clone(),
                            encoding_sum_hash: com.encoding_sum_hash.clone(),

                            zero_sum: encodings.compute_zero_sum(),
                            plaintext: com.encodings.plaintext(),
                            plaintext_salt: com.plaintext_salt.clone(),
                            encoding_sum_salt: com.encoding_sum_salt.clone(),
                        })
                    })
                    .collect::<Result<Vec<_>, ProverError>>()?;

                Ok::<Vec<ProofInput<F>>, ProverError>(coms)
            })
            .flatten()
            .collect::<Vec<_>>();

        let proofs = self.backend.prove(proof_inputs)?;

        Ok((
            Prover {
                backend: self.backend,
                state: state::ProofGenerated {
                    commitments: self.state.commitments,
                },
                pd: PhantomData,
            },
            Proofs { proofs },
        ))
    }
}

#[cfg(test)]
impl<T, F> Prover<T, state::ProofGenerated<T, F>, F>
where
    T: IdSet,
    F: Field + Clone + std::ops::Sub<Output = F> + std::ops::Add<Output = F>,
{
    // Testing only. Returns the backend that can be downcast to a concrete type.
    pub fn backend(self) -> Box<dyn Backend<F>> {
        self.backend
    }
}
