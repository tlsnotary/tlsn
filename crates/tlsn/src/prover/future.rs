//! This module collects futures which are used by the [Prover].

use super::{Prover, ProverError, state};
use futures::Future;
use std::pin::Pin;

/// Prover future which must be polled for the TLS connection to make progress.
pub struct ProverFuture {
    #[allow(clippy::type_complexity)]
    pub(crate) fut: Pin<
        Box<dyn Future<Output = Result<Prover<state::Committed>, ProverError>> + Send + 'static>,
    >,
}

impl Future for ProverFuture {
    type Output = Result<Prover<state::Committed>, ProverError>;

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.fut.as_mut().poll(cx)
    }
}
