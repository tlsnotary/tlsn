//! Future used by the [Prover].

use futures::{AsyncRead, AsyncWrite, Future, FutureExt, future::FusedFuture};
use std::{pin::Pin, task::Poll};

use crate::{
    Error,
    prover::{Prover, ProverControl, state},
};

/// Prover future which must be polled for the TLS connection to make progress.
pub struct ProverFuture<S> {
    pub(crate) state: FutureState<S>,
}

pub(crate) enum FutureState<S> {
    Connected {
        prover: Box<Prover<state::Connected<S>>>,
    },
    Finishing {
        fut:
            Pin<Box<dyn Future<Output = Result<Prover<state::Committed>, Error>> + Send + 'static>>,
    },
    Done,
    Error,
}

impl<S> ProverFuture<S> {
    /// Returns a controller for the prover for advanced functionality.
    pub fn control(&self) -> Option<ProverControl> {
        match &self.state {
            FutureState::Connected { prover } => {
                let decrypt_state = prover.state.tls_client.decrypt();
                Some(ProverControl { decrypt_state })
            }
            _ => None,
        }
    }
}

impl<S> Future for ProverFuture<S>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    type Output = Result<Prover<state::Committed>, Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let state = std::mem::replace(&mut self.state, FutureState::Error);

        match state {
            FutureState::Connected { mut prover } => match prover.poll_unpin(cx)? {
                Poll::Ready(_) => {
                    self.state = FutureState::Finishing {
                        fut: Box::pin(prover.finish()),
                    };
                    self.poll(cx)
                }
                Poll::Pending => {
                    self.state = FutureState::Connected { prover };
                    Poll::Pending
                }
            },
            FutureState::Finishing { mut fut } => match fut.poll_unpin(cx)? {
                Poll::Ready(prover) => {
                    self.state = FutureState::Done;
                    Poll::Ready(Ok(prover))
                }
                Poll::Pending => {
                    self.state = FutureState::Finishing { fut };
                    Poll::Pending
                }
            },
            FutureState::Done => Poll::Ready(Err(
                Error::internal().with_msg("prover future polled after being done")
            )),
            FutureState::Error => Poll::Ready(Err(
                Error::internal().with_msg("prover future is in error state")
            )),
        }
    }
}

impl<S> FusedFuture for ProverFuture<S>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    fn is_terminated(&self) -> bool {
        matches!(self.state, FutureState::Done)
    }
}
