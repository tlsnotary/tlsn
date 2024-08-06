use utils_aio::stream::{ExpectStreamExt, IoStream};

use authdecode_core::{
    backend::traits::{Field, VerifierBackend as Backend},
    encodings::EncodingProvider,
    id::IdCollection,
    msgs::Message,
    verifier::{error::VerifierError, state},
    Verifier as CoreVerifier,
};

#[cfg(feature = "tracing")]
use tracing::{debug, debug_span, instrument, Instrument};

/// Verifier in the AuthDecode protocol.
pub struct Verifier<I, S, F>
where
    I: IdCollection,
    F: Field,
    S: state::VerifierState,
{
    /// The wrapped verifier in the AuthDecode protocol.
    verifier: CoreVerifier<I, S, F>,
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
    /// * `backend` - The zk backend.
    pub fn new(backend: Box<dyn Backend<F>>) -> Self {
        Self {
            verifier: CoreVerifier::new(backend),
        }
    }

    /// Receives the commitments and stores them.
    ///
    /// # Arguments
    ///
    /// * `stream` - The stream for receiving messages from the prover.
    /// * `encoding_provider` - The provider of full encodings for plaintext being committed to.
    #[cfg_attr(feature = "tracing", instrument(level = "debug", skip_all, err))]
    pub async fn receive_commitments<St: IoStream<Message<I, F>> + Send + Unpin>(
        self,
        stream: &mut St,
        encoding_provider: impl EncodingProvider<I> + 'static,
    ) -> Result<Verifier<I, state::CommitmentReceived<I, F>, F>, VerifierError> {
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

impl<I, F> Verifier<I, state::CommitmentReceived<I, F>, F>
where
    I: IdCollection,
    F: Field + std::ops::Add<Output = F> + std::ops::Sub<Output = F> + Clone,
{
    /// Verifies proofs for the commitments received earlier.
    ///
    /// # Arguments
    ///
    /// * `stream` - The stream for receiving messages from the prover.
    #[cfg_attr(feature = "tracing", instrument(level = "debug", skip_all, err))]
    pub async fn verify<St: IoStream<Message<I, F>> + Send + Unpin>(
        self,
        stream: &mut St,
    ) -> Result<Verifier<I, state::VerifiedSuccessfully<I, F>, F>, VerifierError> {
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
