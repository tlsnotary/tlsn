//! This module collects futures which are used by the [Verifier](crate::tls::Verifier).

use super::{OTSenderActor, VerifierError};
use futures::{future::FusedFuture, Future};
use std::pin::Pin;

/// A future which must be polled for the muxer to make progress.
pub(crate) struct MuxFuture {
    pub(crate) fut: Pin<Box<dyn FusedFuture<Output = Result<(), VerifierError>> + Send + 'static>>,
}

impl Future for MuxFuture {
    type Output = Result<(), VerifierError>;

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
    pub(crate) fut:
        Pin<Box<dyn FusedFuture<Output = Result<OTSenderActor, VerifierError>> + Send + 'static>>,
}

impl Future for OTFuture {
    type Output = Result<OTSenderActor, VerifierError>;

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
