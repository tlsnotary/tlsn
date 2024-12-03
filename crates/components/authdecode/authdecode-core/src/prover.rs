use crate::{
    backend::traits::{Field, ProverBackend as Backend},
    encodings::EncodingProvider,
    id::IdCollection,
    msgs::{Commit, Proofs},
    PublicInput,
};

use getset::Getters;
use std::{marker::PhantomData, ops::Add};

#[cfg(feature = "tracing")]
use tracing::{debug, debug_span, instrument, Instrument};

mod commitment;
mod error;
mod state;

pub use commitment::{CommitmentData, CommitmentDetails};
pub use error::ProverError;
pub use state::{Committed, Initialized, ProofGenerated, ProverState};

/// The prover's public and private inputs to the circuit.
#[derive(Clone, Default, Getters)]
pub struct ProverInput<F> {
    /// The public input.
    #[getset(get = "pub")]
    public: PublicInput<F>,
    /// The private input.
    #[getset(get = "pub")]
    private: PrivateInput<F>,
}

/// Private inputs to the AuthDecode circuit.
#[derive(Clone, Default, Getters)]
pub struct PrivateInput<F> {
    /// The plaintext committed to.
    #[getset(get = "pub")]
    plaintext: Vec<u8>,
    /// The salt used to create the commitment to the plaintext.
    #[getset(get = "pub")]
    plaintext_salt: F,
    /// The salt used to create the commitment to the sum of the encodings.
    #[getset(get = "pub")]
    encoding_sum_salt: F,
}

/// Prover in the AuthDecode protocol.
pub struct Prover<I: IdCollection, S: state::ProverState, F: Field> {
    /// The zk backend.
    backend: Box<dyn Backend<F>>,
    /// The current state of the prover.
    state: S,
    pd: PhantomData<I>,
}

impl<I, F> Prover<I, state::Initialized, F>
where
    I: IdCollection,
    F: Field + Add<Output = F>,
{
    /// Creates a new prover.
    ///
    /// # Arguments
    ///
    /// * `backend` - The zk backend.
    pub fn new(backend: Box<dyn Backend<F>>) -> Self {
        Prover {
            backend,
            state: state::Initialized {},
            pd: PhantomData,
        }
    }

    /// Creates a commitment to each element in the `data_set`.
    ///
    /// Returns the prover in a new state and the message to be passed to the verifier.
    ///
    /// # Arguments
    ///
    /// * `data_set` - The set of commitment data to be committed to.
    #[cfg_attr(feature = "tracing", instrument(level = "debug", skip_all, err))]
    #[allow(clippy::type_complexity)]
    pub fn commit(
        self,
        data_set: Vec<CommitmentData<I>>,
    ) -> Result<(Prover<I, Committed<I, F>, F>, Commit<I, F>), ProverError>
    where
        I: IdCollection,
        F: Field + Clone + std::ops::Add<Output = F>,
    {
        // Commit to each commitment data in the set individually.
        let commitments = data_set
            .into_iter()
            .map(|data| data.commit(&self.backend))
            .collect::<Result<Vec<CommitmentDetails<I, F>>, ProverError>>()?;

        Ok((
            Prover {
                backend: self.backend,
                state: Committed {
                    commitments: commitments.clone(),
                },
                pd: PhantomData,
            },
            commitments.into(),
        ))
    }

    /// Creates a commitment to each element in the `data_set` with the provided salts.
    ///
    /// Returns the prover in a new state and the message to be passed to the verifier.
    ///
    /// # Arguments
    ///
    /// * `data_set` - The set of commitment data with salts for each chunk of it.
    #[cfg_attr(feature = "tracing", instrument(level = "debug", skip_all, err))]
    #[allow(clippy::type_complexity)]
    pub fn commit_with_salt(
        self,
        data_set: Vec<(CommitmentData<I>, Vec<Vec<u8>>)>,
    ) -> Result<(Prover<I, Committed<I, F>, F>, Commit<I, F>), ProverError>
    where
        I: IdCollection,
        F: Field + Clone + std::ops::Add<Output = F>,
    {
        // Commit to each element in the set individually.
        let commitments = data_set
            .into_iter()
            .map(|(data, salt)| data.commit_with_salt(&self.backend, salt))
            .collect::<Result<Vec<CommitmentDetails<I, F>>, ProverError>>()?;

        Ok((
            Prover {
                backend: self.backend,
                state: Committed {
                    commitments: commitments.clone(),
                },
                pd: PhantomData,
            },
            commitments.into(),
        ))
    }
}

impl<I, F> Prover<I, Committed<I, F>, F>
where
    I: IdCollection,
    F: Field + Clone + std::ops::Sub<Output = F> + std::ops::Add<Output = F>,
{
    /// Generates zk proofs.
    ///
    /// Returns the prover in a new state and the message to be passed to the verifier.
    ///
    /// # Arguments
    ///
    /// * `encoding_provider` - The provider of full encodings for the plaintext committed to
    ///                         earlier.
    #[cfg_attr(feature = "tracing", instrument(level = "debug", skip_all, err))]
    #[allow(clippy::type_complexity)]
    pub fn prove(
        self,
        encoding_provider: &impl EncodingProvider<I>,
    ) -> Result<(Prover<I, ProofGenerated<I, F>, F>, Proofs), ProverError> {
        // Collect proof inputs for each chunk of plaintext committed to.
        let proof_inputs = self
            .state
            .commitments
            .clone()
            .into_iter()
            .flat_map(|com| {
                let coms = com
                    .chunk_commitments()
                    .iter()
                    .map(|com| {
                        let full_encodings = encoding_provider.get_by_ids(com.ids())?;

                        Ok(ProverInput {
                            public: PublicInput {
                                deltas: full_encodings.compute_deltas::<F>(),
                                plaintext_hash: com.plaintext_hash().clone(),
                                encoding_sum_hash: com.encoding_sum_hash().clone(),
                                zero_sum: full_encodings.compute_zero_sum(),
                            },
                            private: PrivateInput {
                                plaintext: com.encodings().plaintext(),
                                plaintext_salt: com.plaintext_salt().clone(),
                                encoding_sum_salt: com.encoding_sum_salt().clone(),
                            },
                        })
                    })
                    .collect::<Result<Vec<_>, ProverError>>()?;

                Ok::<Vec<ProverInput<F>>, ProverError>(coms)
            })
            .flatten()
            .collect::<Vec<_>>();

        let proofs = self.backend.prove(proof_inputs)?;

        Ok((
            Prover {
                backend: self.backend,
                state: ProofGenerated {
                    commitments: self.state.commitments,
                },
                pd: PhantomData,
            },
            Proofs { proofs },
        ))
    }
}

#[cfg(any(test, feature = "fixtures"))]
impl<I, F> Prover<I, ProofGenerated<I, F>, F>
where
    I: IdCollection,
    F: Field + Clone + std::ops::Sub<Output = F> + std::ops::Add<Output = F>,
{
    // Testing only. Returns the backend that can be downcast to a concrete type.
    pub fn backend(self) -> Box<dyn Backend<F>> {
        self.backend
    }
}
