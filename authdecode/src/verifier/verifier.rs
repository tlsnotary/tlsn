use crate::{
    backend::traits::VerifierBackend as Backend,
    msgs::{Commit, Proofs, VerificationData},
    verifier::{commitment::UnverifiedCommitment, error::VerifierError, state, EncodingProvider},
    InitData,
};
use std::marker::PhantomData;

use crate::{backend::traits::Field, verifier::IdSet};

/// Public inputs to verify one chunk of plaintext.
///
/// Note that the backend may combine multiple `VerificationInputs` in cases when multiple chunks
/// of plaintext are proven with one proof.
#[derive(Default, Clone)]
pub struct VerificationInputs<F>
where
    F: Field,
{
    pub plaintext_hash: F,
    pub encoding_sum_hash: F,
    pub zero_sum: F,
    pub deltas: Vec<F>,
}

/// Verifier in the AuthDecode protocol.
pub struct Verifier<T, S: state::VerifierState, F> {
    /// Backend for zk proof verification.
    backend: Box<dyn Backend<F>>,
    /// State of the verifier.
    state: S,
    phantom: PhantomData<T>,
}

impl<T, F> Verifier<T, state::Initialized, F>
where
    T: IdSet,
    F: Field,
{
    /// Creates a new verifier.
    pub fn new(backend: Box<dyn Backend<F>>) -> Self {
        Verifier {
            backend,
            state: state::Initialized {},
            phantom: PhantomData,
        }
    }

    /// Receives the commitments and returns the data needed by the prover to check the authenticity
    /// of the encodings.
    ///
    /// # Arguments
    /// * `commitments` - A prover's message containing commitments.
    /// * `encoding_provider` - A provider of full encodings.
    /// * `init_data` - Data to pass to the prover for initialization of the encoding verifier.
    pub fn receive_commitments(
        self,
        commitments: Commit<T, F>,
        encoding_provider: impl EncodingProvider<T>,
        init_data: InitData,
    ) -> Result<
        (
            Verifier<T, state::CommitmentReceived<T, F>, F>,
            VerificationData,
        ),
        VerifierError,
    > {
        let mut commitments: Vec<UnverifiedCommitment<T, F>> = commitments
            .into_vec_commitment(self.backend.chunk_size() * 8)
            .map_err(|e| VerifierError::StdIoError(e.to_string()))?;

        // Store full encodings with each commitment details.
        for com in &mut commitments {
            let full_encodings = encoding_provider.get_by_ids(com.ids())?.convert();
            com.set_full_encodings(full_encodings);
        }

        Ok((
            Verifier {
                backend: self.backend,
                state: state::CommitmentReceived { commitments },
                phantom: PhantomData,
            },
            VerificationData { init_data },
        ))
    }
}

impl<T, F> Verifier<T, state::CommitmentReceived<T, F>, F>
where
    T: IdSet,
    F: Field + std::ops::Add<Output = F> + std::ops::Sub<Output = F> + Clone,
{
    /// Verifies proofs for the commitments received earlier.
    ///
    /// # Arguments
    /// * `proofs` - The prover's message containing proofs.
    pub fn verify(
        self,
        proofs: Proofs,
    ) -> Result<Verifier<T, state::VerifiedSuccessfully<T, F>, F>, VerifierError> {
        let Proofs { proofs } = proofs;

        // Compute public inputs to verify each chunk of plaintext committed to.
        let public_inputs = self
            .state
            .commitments
            .iter()
            .flat_map(|com| &com.chunk_commitments)
            .map(|com| {
                VerificationInputs {
                    plaintext_hash: com.plaintext_hash.clone(),
                    encoding_sum_hash: com.encoding_sum_hash.clone(),
                    // It is safe to `unwrap()` since `full_encodings` were set earlier when the
                    // commitments were received.
                    zero_sum: com.full_encodings.as_ref().unwrap().compute_zero_sum(),
                    deltas: com.full_encodings.as_ref().unwrap().compute_deltas(),
                }
            })
            .collect::<Vec<_>>();

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
