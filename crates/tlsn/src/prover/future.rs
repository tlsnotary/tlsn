//! This module collects futures which are used by the [Prover].

use futures::{AsyncRead, AsyncWrite, Future, FutureExt, future::FusedFuture};
use std::{pin::Pin, task::Poll};

use crate::{
    Error,
    prover::{Prover, ProverControl, state},
};

/// Prover future which must be polled for the TLS connection to make progress.
pub struct ProverFuture<S> {
    pub(crate) prover: Option<Prover<state::Connected<S>>>,
}

impl<S> ProverFuture<S> {
    /// Returns a controller for the prover for advanced functionality.
    pub fn control(&self) -> ProverControl {
        let decrypt_state = self
            .prover
            .as_ref()
            .expect("prover should be available")
            .state
            .tls_client
            .decrypt();

        ProverControl { decrypt_state }
    }
}

impl<S> Future for ProverFuture<S>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    type Output = Result<Prover<state::Committed>, Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        if let Some(prover) = self.prover.as_mut() {
            let poll = prover.poll_unpin(cx)?;

            if poll.is_ready() {
                let prover = self.prover.take().expect("prover should be available");
                return Poll::Ready(prover.finish());
            }
        }
        Poll::Pending
    }
}

impl<S> FusedFuture for ProverFuture<S>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    fn is_terminated(&self) -> bool {
        self.prover.is_none()
    }
}
