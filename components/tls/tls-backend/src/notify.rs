use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use futures::future::FusedFuture;

/// A notifier which can be used by the backend.
#[derive(Default)]
pub struct BackendNotifier {
    state: Arc<Mutex<State>>,
}

impl BackendNotifier {
    /// Creates a new notifier.
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                ready: false,
                waker: None,
            })),
        }
    }

    /// Gets the notification.
    pub fn get(&self) -> BackendNotify {
        BackendNotify {
            state: self.state.clone(),
        }
    }

    /// Clears the notification.
    pub fn clear(&self) {
        let mut state = self.state.lock().unwrap();
        state.ready = false;
    }

    /// Sets the notification.
    pub fn set(&self) {
        let mut state = self.state.lock().unwrap();
        state.ready = true;
        if let Some(waker) = state.waker.take() {
            waker.wake();
        }
    }
}

#[derive(Default)]
struct State {
    ready: bool,
    waker: Option<Waker>,
}

/// A future which resolves when a notification is received from the backend.
pub struct BackendNotify {
    state: Arc<Mutex<State>>,
}

impl BackendNotify {
    /// Creates a dummy notifier that does nothing.
    pub fn dummy() -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                ready: false,
                waker: None,
            })),
        }
    }
}

impl Future for BackendNotify {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = self.state.lock().unwrap();
        if state.ready {
            Poll::Ready(())
        } else {
            state.waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

impl FusedFuture for BackendNotify {
    fn is_terminated(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backend_notify() {
        let notifier = BackendNotifier::new();
        let notify = notifier.get();

        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(10));
            notifier.set();
        });

        futures::executor::block_on(notify);
    }
}
