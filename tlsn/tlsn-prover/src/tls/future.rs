//! This module collects futures which are used by the [Prover].

use super::{state, Prover, ProverControl, ProverError};
use futures::{future::FusedFuture, Future};
use std::pin::Pin;

/// Prover future which must be polled for the TLS connection to make progress.
pub struct ProverFuture {
    #[allow(clippy::type_complexity)]
    pub(crate) fut:
        Pin<Box<dyn Future<Output = Result<Prover<state::Closed>, ProverError>> + Send + 'static>>,
    pub(crate) ctrl: ProverControl,
}

impl ProverFuture {
    /// Returns a controller for the prover for advanced functionality.
    pub fn control(&self) -> ProverControl {
        self.ctrl.clone()
    }
}

impl Future for ProverFuture {
    type Output = Result<Prover<state::Closed>, ProverError>;

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.fut.as_mut().poll(cx)
    }
}

/// A future which must be polled for the muxer to make progress.
pub(crate) struct MuxFuture {
    pub(crate) fut: Pin<Box<dyn FusedFuture<Output = Result<(), ProverError>> + Send + 'static>>,
}

impl Future for MuxFuture {
    type Output = Result<(), ProverError>;

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.fut.as_mut().poll(cx)
    }
}

impl FusedFuture for MuxFuture {
    fn is_terminated(&self) -> bool {
        self.fut.is_terminated()
    }
}

/// A future which must be polled for the Oblivious Transfer protocol to make progress.
pub(crate) struct OTFuture {
    pub(crate) fut: Pin<Box<dyn FusedFuture<Output = Result<(), ProverError>> + Send + 'static>>,
}

impl Future for OTFuture {
    type Output = Result<(), ProverError>;

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.fut.as_mut().poll(cx)
    }
}

impl FusedFuture for OTFuture {
    fn is_terminated(&self) -> bool {
        self.fut.is_terminated()
    }
}
