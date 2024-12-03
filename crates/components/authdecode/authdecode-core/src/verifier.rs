use std::marker::PhantomData;

use crate::{
    backend::traits::{Field, VerifierBackend as Backend},
    encodings::EncodingProvider,
    id::IdCollection,
    msgs::{Commit, Proofs},
    PublicInput,
};

#[cfg(feature = "tracing")]
use tracing::{debug, debug_span, instrument, Instrument};

mod commitment;
mod error;
mod state;

pub use commitment::VerifiedCommitment;
pub(crate) use commitment::{UnverifiedChunkCommitment, UnverifiedCommitment};
pub use error::VerifierError;
pub use state::{CommitmentReceived, Initialized, VerifiedSuccessfully, VerifierState};

/// Verifier in the AuthDecode protocol.
pub struct Verifier<I, S, F>
where
    I: IdCollection,
    F: Field,
    S: state::VerifierState,
{
    /// The backend for zk proof verification.
    backend: Box<dyn Backend<F>>,
    /// The state of the verifier.
    state: S,
    phantom: PhantomData<I>,
}

impl<I, F> Verifier<I, state::Initialized, F>
where
    I: IdCollection,
    F: Field,
{
    /// Creates a new verifier.
    ///
    /// # Arguments
    ///
    /// `backend` - The backend for zk proof verification
    pub fn new(backend: Box<dyn Backend<F>>) -> Self {
        Verifier {
            backend,
            state: state::Initialized {},
            phantom: PhantomData,
        }
    }

    /// Receives the commitments and stores them.
    ///
    /// Returns the verifier in a new state.
    ///
    /// # Arguments
    ///
    /// * `commitments` - The prover's message containing commitments.
    /// * `encoding_provider` - The provider of full encodings.
    #[cfg_attr(feature = "tracing", instrument(level = "debug", skip_all, err))]
    pub fn receive_commitments(
        self,
        commitments: Commit<I, F>,
    ) -> Result<Verifier<I, state::CommitmentReceived<I, F>, F>, VerifierError> {
        let commitments: Vec<UnverifiedCommitment<I, F>> =
            commitments.into_vec_commitment(self.backend.chunk_size())?;

        Ok(Verifier {
            backend: self.backend,
            state: state::CommitmentReceived { commitments },
            phantom: PhantomData,
        })
    }
}

impl<I, F> Verifier<I, state::CommitmentReceived<I, F>, F>
where
    I: IdCollection,
    F: Field + std::ops::Add<Output = F> + std::ops::Sub<Output = F> + Clone,
{
    /// Verifies proofs for the commitments received earlier.
    ///
    /// Returns the verifier in a new state.
    ///
    /// # Arguments
    /// * `proofs` - The prover's message containing proofs.
    /// * `encoding_provider` - The provider of the encodings for plaintext bits.
    #[cfg_attr(feature = "tracing", instrument(level = "debug", skip_all, err))]
    pub fn verify(
        self,
        proofs: Proofs,
        encoding_provider: &(impl EncodingProvider<I> + 'static),
    ) -> Result<Verifier<I, state::VerifiedSuccessfully<I, F>, F>, VerifierError> {
        let Proofs { proofs } = proofs;

        // Compute public inputs to verify each chunk of plaintext committed to.
        let public_inputs = self
            .state
            .commitments
            .iter()
            .flat_map(|com| com.chunk_commitments())
            .map(|com| {
                let encodings = encoding_provider.get_by_ids(com.ids())?;

                Ok(PublicInput {
                    plaintext_hash: com.plaintext_hash().clone(),
                    encoding_sum_hash: com.encoding_sum_hash().clone(),
                    zero_sum: encodings.compute_zero_sum(),
                    deltas: encodings.compute_deltas(),
                })
            })
            .collect::<Result<Vec<_>, VerifierError>>()?;

        self.backend.verify(public_inputs, proofs)?;

        Ok(Verifier {
            backend: self.backend,
            state: state::VerifiedSuccessfully {
                commitments: self
                    .state
                    .commitments
                    .into_iter()
                    .map(|com| com.into())
                    .collect(),
            },
            phantom: PhantomData,
        })
    }
}

impl<I, F> Verifier<I, state::VerifiedSuccessfully<I, F>, F>
where
    I: IdCollection,
    F: Field + std::ops::Add<Output = F> + std::ops::Sub<Output = F> + Clone,
{
    /// Returns the verified comitments.
    pub fn commitments(&self) -> &Vec<VerifiedCommitment<I, F>> {
        &self.state.commitments
    }
}
