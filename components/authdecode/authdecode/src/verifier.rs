use utils_aio::stream::{ExpectStreamExt, IoStream};

use authdecode_core::{
    backend::traits::{Field, VerifierBackend as Backend},
    encodings::EncodingProvider,
    id::IdSet,
    msgs::Message,
    verifier::{error::VerifierError, state},
    Verifier as CoreVerifier,
};

/// Verifier in the AuthDecode protocol.
pub struct Verifier<T, S, F>
where
    T: IdSet,
    F: Field,
    S: state::VerifierState,
{
    verifier: CoreVerifier<T, S, F>,
}

impl<T, F> Verifier<T, state::Initialized, F>
where
    T: IdSet,
    F: Field,
{
    /// Creates a new verifier.
    pub fn new(backend: Box<dyn Backend<F>>) -> Self {
        Self {
            verifier: CoreVerifier::new(backend),
        }
    }

    pub async fn receive_commitments<St: IoStream<Message<T, F>> + Send + Unpin>(
        self,
        stream: &mut St,
        encoding_provider: impl EncodingProvider<T> + 'static,
    ) -> Result<Verifier<T, state::CommitmentReceived<T, F>, F>, VerifierError> {
        let commitments = stream
            .expect_next()
            .await?
            .try_into_commit()
            .map_err(VerifierError::from)?;

        Ok(Verifier {
            verifier: self
                .verifier
                .receive_commitments(commitments, encoding_provider)?,
        })
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
    pub async fn verify<St: IoStream<Message<T, F>> + Send + Unpin>(
        self,
        stream: &mut St,
    ) -> Result<Verifier<T, state::VerifiedSuccessfully<T, F>, F>, VerifierError> {
        let proofs = stream
            .expect_next()
            .await?
            .try_into_proofs()
            .map_err(VerifierError::from)?;

        Ok(Verifier {
            verifier: self.verifier.verify(proofs)?,
        })
    }
}
