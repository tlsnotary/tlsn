//! Future used by the [Prover].

use futures::{AsyncRead, AsyncWrite, AsyncWriteExt, Future, FutureExt, future::FusedFuture};
use std::{pin::Pin, task::Poll};

use crate::{
    Error,
    prover::{Prover, state},
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
        fut: Pin<Box<dyn Future<Output = Result<Prover<state::Committed>, Error>> + Send>>,
    },
    Done,
    Error,
}

impl<S> Future for ProverFuture<S>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    type Output = Result<Prover<state::Committed>, Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let state = std::mem::replace(&mut self.state, FutureState::Error);

        match state {
            FutureState::Connected { mut prover } => match prover.poll(cx) {
                Poll::Ready(Ok(_)) => {
                    self.state = FutureState::Finishing {
                        fut: Box::pin(prover.finish()),
                    };
                    self.poll(cx)
                }
                // Close the connection handles before yielding the error, so
                // that readers of the `TlsConnection` and the server socket
                // observe closure instead of waiting indefinitely. Closing is
                // best-effort: close errors are ignored in favor of the
                // original error.
                Poll::Ready(Err(error)) => {
                    let state::Connected {
                        mut client_io,
                        mut server_socket,
                        ..
                    } = prover.state;

                    self.state = FutureState::Finishing {
                        fut: Box::pin(async move {
                            let _ = client_io.close().await;
                            let _ = server_socket.close().await;
                            Err(error)
                        }),
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
