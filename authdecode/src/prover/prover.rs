use crate::{
    backend::traits::{Field, ProverBackend as Backend},
    bitid::IdSet,
    encodings::EncodingProvider,
    msgs::{Commit, Proofs},
    prover::{error::ProverError, state},
    utils::boolvec_to_u8vec,
    AsAny,
};

use super::commitment::{CommitmentData, CommitmentDetails};
use std::{marker::PhantomData, ops::Add};

// Public and private inputs to the circuit.
#[derive(Clone, Default)]
pub struct ProofInput<F> {
    // Public
    pub plaintext_hash: F,
    pub encoding_sum_hash: F,
    /// The sum of encodings which encode the 0 bit.
    pub zero_sum: F,
    /// An arithmetic difference between the encoding of bit value 1 and encoding of bit value 0 for
    /// each bit of the plaintext.
    pub deltas: Vec<F>,

    // Private
    pub plaintext: Vec<u8>,
    pub plaintext_salt: F,
    pub encoding_sum_salt: F,
}

/// Prover in the AuthDecode protocol.
pub struct Prover<T: IdSet, S: state::ProverState, F: Field> {
    backend: Box<dyn Backend<F>>,
    pub state: S,
    phantom: PhantomData<T>,
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
            phantom: PhantomData,
        }
    }

    /// Creates a commitment to each element in the `data_set`.
    #[allow(clippy::type_complexity)]
    pub fn commit(
        self,
        data_set: Vec<CommitmentData<T>>,
    ) -> Result<(Prover<T, state::Committed<T, F>, F>, Commit<T, F>), ProverError>
    where
        T: IdSet,
        F: Field + Clone + std::ops::Add<Output = F>,
    {
        // Commit to each commitment data in the set individually.
        let commitments = data_set
            .into_iter()
            .map(|data| data.commit(&self.backend))
            .collect::<Result<Vec<CommitmentDetails<T, F>>, ProverError>>()?;

        Ok((
            Prover {
                backend: self.backend,
                state: state::Committed {
                    commitments: commitments.clone(),
                },
                phantom: PhantomData,
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
    ) -> Result<(Prover<T, state::ProofCreated<T, F>, F>, Proofs), ProverError> {
        let commitments = self.state.commitments.clone();

        // Collect proof inputs for each chunk of plaintext committed to.
        let all_inputs = commitments
            .clone()
            .into_iter()
            .flat_map(|com| {
                let coms = com
                    .chunk_commitments
                    .into_iter()
                    .map(|com| {
                        let encodings = encoding_provider.get_by_ids(com.ids())?.convert();

                        Ok(ProofInput {
                            deltas: encodings.compute_deltas::<F>(),
                            plaintext_hash: com.plaintext_hash.clone(),
                            encoding_sum_hash: com.encoding_sum_hash.clone(),

                            zero_sum: encodings.compute_zero_sum(),
                            plaintext: boolvec_to_u8vec(&com.encodings.plaintext()),
                            plaintext_salt: com.plaintext_salt.clone(),
                            encoding_sum_salt: com.encoding_sum_salt.clone(),
                        })
                    })
                    .collect::<Result<Vec<_>, ProverError>>()?;

                Ok::<Vec<ProofInput<F>>, ProverError>(coms)
            })
            .flatten()
            .collect::<Vec<_>>();

        let proofs = self.backend.prove(all_inputs)?;

        Ok((
            Prover {
                backend: self.backend,
                state: state::ProofCreated {
                    commitments,
                    proofs: proofs.clone(),
                },
                phantom: PhantomData,
            },
            Proofs { proofs },
        ))
    }
}

impl<T, F> Prover<T, state::ProofCreated<T, F>, F>
where
    T: IdSet,
    F: Field + Clone + std::ops::Sub<Output = F> + std::ops::Add<Output = F>,
{
    // Testing only. Returns the backend that can be downcast to a concrete type.
    pub fn backend(self) -> Box<dyn Backend<F>> {
        self.backend
    }
}

use crate::backend::traits;
pub trait NewTrait<F>: traits::ProverBackend<F> + AsAny
where
    F: Field,
{
}
