use tokio::sync::broadcast::{channel, error::RecvError, Sender};

/// An adaptive barrier
///
/// This allows to change the number of barriers dynamically.
/// Code is taken from https://users.rust-lang.org/t/a-poor-man-async-adaptive-barrier/68118
#[derive(Debug, Clone)]
pub struct AdaptiveBarrier {
    inner: Sender<Empty>,
}

impl AdaptiveBarrier {
    /// Wait in order to perform task synchronization
    ///
    /// Waits for all other barriers who have been cloned from this one
    /// to also call `wait`
    pub async fn wait(self) {
        let mut receiver = self.inner.subscribe();
        drop(self.inner);
        match receiver.recv().await {
            Ok(_) => unreachable!(),
            Err(RecvError::Lagged(_)) => unreachable!(),
            Err(RecvError::Closed) => (),
        }
    }

    pub fn new() -> Self {
        Self {
            // even though we will not receive any data, we still
            // need to set the channel's capacity to the required minimum 1
            inner: channel(1).0,
        }
    }
}

impl Default for AdaptiveBarrier {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy)]
enum Empty {}

#[cfg(test)]
mod tests {
    use super::AdaptiveBarrier;
    use std::{mem::replace, sync::Arc, time::Duration};
    use tokio::sync::Mutex;

    #[derive(Debug, Clone)]
    struct Waiter {
        counter: Arc<Mutex<Vec<usize>>>,
        barrier: AdaptiveBarrier,
    }

    impl Waiter {
        fn new(counter: &Arc<Mutex<Vec<usize>>>) -> Self {
            Self {
                counter: Arc::clone(counter),
                barrier: AdaptiveBarrier::new(),
            }
        }

        // add a new value to the counter. if no values are present in the
        // counter, the new value will be 1.
        async fn count(self) {
            let mut counter = self.counter.lock().await;
            let last = counter.last().copied().unwrap_or_default();
            counter.push(last + 1);
        }

        async fn count_wait(mut self) {
            // use `replace()` because we can't call `self.barrier.wait().await;` here
            let barrier = replace(&mut self.barrier, AdaptiveBarrier::new());
            barrier.wait().await;
            self.count().await;
        }
    }

    // We expect that 0 is not the first number in the counter because we do not use
    // the barrier in this test
    #[tokio::test]
    async fn test_adaptive_barrier_no_wait() {
        let counter = Arc::new(Mutex::new(vec![]));

        let waiter = Waiter::new(&counter);
        let waiter_2 = waiter.clone();
        let waiter_3 = waiter.clone();

        let task = tokio::spawn(async move {
            waiter.count().await;
        });
        let task_2 = tokio::spawn(async move {
            waiter_2.count().await;
        });

        // the reason why we are not using here:
        // _ = tokio::join!(task, task_2);
        // is to make this test comparable to `test_adaptive_barrier_wait`
        tokio::time::sleep(Duration::from_millis(1000)).await;
        {
            // Add 0 to counter. But this will not be the first number
            // since `task` and `task_2` were already able to add to
            // the counter.
            counter.lock().await.push(0);
        }

        // both tasks must be finished now
        assert!(task.is_finished() && task_2.is_finished());

        let task_3 = tokio::spawn(async move {
            waiter_3.count().await;
        });
        _ = tokio::join!(task, task_2, task_3);
        assert_ne!(*counter.lock().await.first().unwrap(), 0);
    }

    // Now we use `count_wait` instead of `count` so 0 should be the first number
    #[tokio::test]
    async fn test_adaptive_barrier_wait() {
        let counter = Arc::new(Mutex::new(vec![]));

        let waiter = Waiter::new(&counter);
        let waiter_2 = waiter.clone();
        let waiter_3 = waiter.clone();

        let task = tokio::spawn(async move {
            waiter.count_wait().await;
        });
        let task_2 = tokio::spawn(async move {
            waiter_2.count_wait().await;
        });

        tokio::time::sleep(Duration::from_millis(1000)).await;
        {
            counter.lock().await.push(0);
        }

        // both tasks must NOT be finished yet
        assert!(!task.is_finished() && !task_2.is_finished());

        // Now we wait for the last barrier, so all tasks can start counting
        let task_3 = tokio::spawn(async move {
            waiter_3.count_wait().await;
        });
        _ = tokio::join!(task, task_2, task_3);
        assert_eq!(*counter.lock().await.first().unwrap(), 0);
    }
}
