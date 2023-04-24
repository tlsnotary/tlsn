use std::pin::Pin;

use futures::Future;

use crate::Thread;

/// A closure which takes a mutable reference to a thread and returns a boxed future.
type ThreadClosure<'a, T, R> =
    Box<dyn for<'b> FnOnce(&'b mut T) -> Pin<Box<dyn Future<Output = R> + 'b>> + 'a>;

/// An MPC thread pool.
pub struct ThreadPool<T> {
    threads: Vec<T>,
}

/// A thread pool scope.
pub struct Scope<'a, T, R> {
    pool: &'a mut ThreadPool<T>,
    closures: Vec<ThreadClosure<'a, T, R>>,
}

impl<'a, T, R> Scope<'a, T, R> {
    /// Adds a new task to be run in the scope.
    ///
    /// # Return type
    ///
    /// All tasks must have the same return type.
    ///
    /// # Order
    ///
    /// The order of the closures provided _must_ be the same for all parties in the MPC.
    ///
    /// # Boxed Future
    ///
    /// The closures provided must return a boxed future. This is due to higher-ranked trait bound
    /// limitation with closures. See [this issue](https://github.com/rust-lang/rust/issues/70263) for more details.
    ///
    /// # Note
    ///
    /// The futures are evenly distributed across the threads in the pool, but the pool does not
    /// perform any load balancing. This can cause some threads to be idle while others are still
    /// finishing up. Care should be taken to ensure that the futures all have roughly the same
    /// processing time.
    pub fn push<F>(&mut self, f: F)
    where
        F: for<'b> FnOnce(&'b mut T) -> Pin<Box<dyn Future<Output = R> + 'b>> + 'a,
    {
        self.closures.push(Box::new(f));
    }

    /// Runs all tasks added to the scope queue.
    pub async fn wait(self) -> Vec<R> {
        let thread_count = self.pool.threads.len();
        // Create a queue for each thread.
        let mut queues: Vec<_> = (0..thread_count).map(|_| Vec::new()).collect();

        // Distribute the futures round-robin across the queues.
        let mut count = 0;
        self.closures
            .into_iter()
            .zip((0..thread_count).cycle())
            .for_each(|(closure, queue_idx)| {
                count += 1;
                queues[queue_idx].push(closure);
            });

        // Create an iterator of futures which will run the futures in each queue.
        let futs: Vec<_> = queues
            .into_iter()
            .zip(self.pool.threads.iter_mut())
            .map(|(closures, thread)| async move {
                let mut results = Vec::with_capacity(closures.len());
                for closure in closures {
                    results.push(closure(thread).await);
                }
                results.reverse();
                results
            })
            .collect();

        let mut queue_results = futures::future::join_all(futs).await;
        let mut results = Vec::with_capacity(count);
        // Interleave the results from each queue in their original order.
        for queue_idx in (0..thread_count).cycle() {
            if results.len() == count {
                break;
            }
            if let Some(result) = queue_results[queue_idx].pop() {
                results.push(result);
            }
        }

        results
    }
}

impl<T> ThreadPool<T>
where
    T: Thread + 'static,
{
    /// Creates a new thread pool.
    pub(crate) fn new(threads: Vec<T>) -> Self {
        Self { threads }
    }

    /// Returns a new thread pool scope.
    pub fn new_scope<R>(&mut self) -> Scope<'_, T, R> {
        Scope {
            pool: self,
            closures: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{protocol::deap::mock::create_mock_deap_vm, Decode, Execute, Vm, VmError};
    use mpc_circuits::circuits::AES128;

    async fn test_fn_leader<T: Thread + Execute + Decode>(
        thread: &mut T,
        n: usize,
    ) -> Result<[u8; 16], VmError> {
        let key = thread.new_private_input(&format!("key/{n}"), Some([0u8; 16]))?;
        let msg = thread.new_private_input(&format!("msg/{n}"), Some([0u8; 16]))?;
        let ciphertext = thread.new_output::<[u8; 16]>(&format!("ciphertext/{n}"))?;

        thread
            .execute(AES128.clone(), &[key, msg], &[ciphertext.clone()])
            .await?;

        let mut values = thread.decode(&[ciphertext]).await?;

        Ok(values.pop().unwrap().try_into().unwrap())
    }

    async fn test_fn_follower<T: Thread + Execute + Decode>(
        thread: &mut T,
        n: usize,
    ) -> Result<[u8; 16], VmError> {
        let key = thread.new_private_input::<[u8; 16]>(&format!("key/{n}"), None)?;
        let msg = thread.new_private_input::<[u8; 16]>(&format!("msg/{n}"), None)?;
        let ciphertext = thread.new_output::<[u8; 16]>(&format!("ciphertext/{n}"))?;

        thread
            .execute(AES128.clone(), &[key, msg], &[ciphertext.clone()])
            .await?;

        let mut values = thread.decode(&[ciphertext]).await?;

        Ok(values.pop().unwrap().try_into().unwrap())
    }

    #[tokio::test]
    async fn test_thread_pool() {
        let (mut leader, mut follower) = create_mock_deap_vm("test_vm").await;

        let (mut leader_pool, mut follower_pool) = futures::try_join!(
            leader.new_thread_pool("test_pool", 4),
            follower.new_thread_pool("test_pool", 4),
        )
        .unwrap();

        let mut leader_scope = leader_pool.new_scope();
        let mut follower_scope = follower_pool.new_scope();

        for block in 0..10 {
            leader_scope.push(move |thread| Box::pin(test_fn_leader(thread, block)));
            follower_scope.push(move |thread| Box::pin(test_fn_follower(thread, block)));
        }

        let (leader_results, follower_results) =
            futures::join!(leader_scope.wait(), follower_scope.wait());

        let leader_results = leader_results
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let follower_results = follower_results
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(leader_results, follower_results);
    }
}
