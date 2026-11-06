//! Future utilities.

use std::{future::Future, pin::Pin, task::Poll};

/// The state of the auxiliary future after [`poll_with`] returns.
pub(crate) enum Aux<A: Future> {
    /// The auxiliary future completed while the main future was polled.
    Completed(A::Output),
    /// The auxiliary future is still pending and is returned for later
    /// examination.
    Pending(Pin<Box<A>>),
}

/// Polls `main` to completion while also polling `aux`.
///
/// `main` has priority: it is polled first, and if both futures become ready
/// during the same poll, only `main` completes.
///
/// If `aux` completes while `main` is pending, its output is retained and
/// returned. If `main` completes first, `aux` is not dropped; it is returned
/// as [`Aux::Pending`] so the caller can examine or continue polling it.
pub(crate) async fn poll_with<M, A>(main: M, aux: A) -> (M::Output, Aux<A>)
where
    M: Future,
    A: Future,
{
    let mut main = Box::pin(main);
    let mut aux = Box::pin(aux);
    let mut aux_output = None;

    let main_output = futures::future::poll_fn(|cx| {
        // `main` is polled first so that it wins if both are ready.
        if let Poll::Ready(output) = main.as_mut().poll(cx) {
            return Poll::Ready(output);
        }

        // Once the auxiliary future completes, stop polling it.
        if aux_output.is_none() {
            match aux.as_mut().poll(cx) {
                Poll::Ready(output) => {
                    aux_output = Some(output);
                    // Re-poll `main` in case the auxiliary future's completion
                    // unblocked it.
                    cx.waker().wake_by_ref();
                }
                Poll::Pending => {}
            }
        }

        Poll::Pending
    })
    .await;

    let aux = match aux_output {
        Some(output) => Aux::Completed(output),
        None => Aux::Pending(aux),
    };

    (main_output, aux)
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        future::{poll_fn, ready},
        rc::Rc,
        task::Poll,
    };

    use super::{Aux, poll_with};

    #[test]
    fn main_wins_when_both_are_ready() {
        let aux_polls = Rc::new(Cell::new(0));
        let aux = {
            let polls = aux_polls.clone();
            poll_fn(move |_| {
                polls.set(polls.get() + 1);
                Poll::Ready("aux")
            })
        };

        let (main, aux) = futures::executor::block_on(poll_with(ready("main"), aux));

        assert_eq!(main, "main");
        assert_eq!(aux_polls.get(), 0, "aux must not run when main is ready");

        // The auxiliary future is still available for later examination.
        let Aux::Pending(aux) = aux else {
            panic!("aux should still be pending");
        };
        assert_eq!(futures::executor::block_on(aux), "aux");
    }

    #[test]
    fn aux_is_dragged_until_main_completes() {
        let main_polls = Rc::new(Cell::new(0));
        let main = {
            let polls = main_polls.clone();
            poll_fn(move |_| {
                polls.set(polls.get() + 1);
                if polls.get() == 1 {
                    Poll::Pending
                } else {
                    Poll::Ready("main")
                }
            })
        };

        let (main, aux) = futures::executor::block_on(poll_with(main, ready("aux")));

        assert_eq!(main, "main");
        assert_eq!(main_polls.get(), 2);
        assert!(
            matches!(aux, Aux::Completed("aux")),
            "aux should have completed while main was pending"
        );
    }

    #[test]
    fn main_completion_returns_pending_aux() {
        let (main, aux) = futures::executor::block_on(poll_with(
            ready("main"),
            futures::future::pending::<&str>(),
        ));

        assert_eq!(main, "main");
        assert!(matches!(aux, Aux::Pending(_)));
    }
}
