//! This module collects futures which are used by the [Prover].

use super::{Prover, ProverControl, ProverError, state};
use futures::Future;
use std::pin::Pin;

/// Prover future which must be polled for the TLS connection to make progress.
pub struct ProverFuture<Io> {
    #[allow(clippy::type_complexity)]
    pub(crate) fut: Pin<
        Box<
            dyn Future<Output = Result<Prover<state::Committed<Io>>, ProverError>> + Send + 'static,
        >,
    >,
    pub(crate) ctrl: ProverControl,
}

impl<Io> ProverFuture<Io> {
    /// Returns a controller for the prover for advanced functionality.
    pub fn control(&self) -> ProverControl {
        self.ctrl.clone()
    }
}

impl<Io> Future for ProverFuture<Io> {
    type Output = Result<Prover<state::Committed<Io>>, ProverError>;

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.fut.as_mut().poll(cx)
    }
}
