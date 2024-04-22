use futures_util::SinkExt;
use std::ops::Add;
use utils_aio::sink::IoSink;

use authdecode_core::{
    backend::traits::{Field, ProverBackend as Backend},
    encodings::EncodingProvider,
    id::IdSet,
    msgs::Message,
    prover::{commitment::CommitmentData, error::ProverError, state},
    Prover as CoreProver,
};

/// Prover in the AuthDecode protocol.
pub struct Prover<T, S, F>
where
    T: IdSet,
    F: Field + Add<Output = F>,
    S: state::ProverState,
{
    prover: CoreProver<T, S, F>,
}

impl<T, F> Prover<T, state::Initialized, F>
where
    T: IdSet,
    F: Field + Add<Output = F>,
{
    /// Creates a new prover.
    pub fn new(backend: Box<dyn Backend<F>>) -> Self {
        Self {
            prover: CoreProver::new(backend),
        }
    }
}

impl<T, F> Prover<T, state::Initialized, F>
where
    T: IdSet,
    F: Field + Add<Output = F>,
{
    /// Creates a commitment to each element in the `data_set`.
    pub async fn commit<Si: IoSink<Message<T, F>> + Send + Unpin>(
        self,
        sink: &mut Si,
        data_set: &[CommitmentData<T>],
    ) -> Result<Prover<T, state::Committed<T, F>, F>, ProverError>
    where
        T: IdSet,
        F: Field + Clone + std::ops::Add<Output = F>,
    {
        let (core_prover, msg) = self.prover.commit(data_set)?;

        sink.send(Message::Commit(msg)).await?;

        Ok(Prover {
            prover: core_prover,
        })
    }
}

impl<T, F> Prover<T, state::Committed<T, F>, F>
where
    T: IdSet,
    F: Field + Clone + std::ops::Sub<Output = F> + std::ops::Add<Output = F>,
{
    /// Generates zk proofs.
    pub async fn prove<Si: IoSink<Message<T, F>> + Send + Unpin>(
        self,
        sink: &mut Si,
        encoding_provider: impl EncodingProvider<T>,
    ) -> Result<Prover<T, state::ProofGenerated<T, F>, F>, ProverError> {
        let (prover, msg) = self.prover.prove(encoding_provider)?;

        sink.send(Message::Proofs(msg)).await?;

        Ok(Prover { prover })
    }
}
