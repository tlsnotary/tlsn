use async_trait::async_trait;
use futures::channel::oneshot;

/// Allows to spawn a closure on a thread outside of the async runtime
///
/// This allows to perform CPU-intensive tasks without blocking the runtime.
#[async_trait]
pub trait CPUBackend {
    /// Spawn the closure in a separate thread and await the result
    async fn spawn<
        F: FnOnce() -> Result<T, E> + Send + 'static,
        T: Send + 'static,
        E: std::error::Error + From<oneshot::Canceled> + Send + 'static,
    >(
        closure: F,
    ) -> Result<T, E>;
}

/// A CPU backend that uses Rayon
pub struct RayonBackend;

#[async_trait]
impl CPUBackend for RayonBackend {
    async fn spawn<
        F: FnOnce() -> Result<T, E> + Send + 'static,
        T: Send + 'static,
        E: std::error::Error + From<oneshot::Canceled> + Send + 'static,
    >(
        closure: F,
    ) -> Result<T, E> {
        let (sender, receiver) = oneshot::channel();
        rayon::spawn(move || {
            _ = sender.send(closure());
        });

        receiver.await?
    }
}

#[cfg(test)]
mod tests {
    use super::{CPUBackend, RayonBackend};
    use futures::channel::oneshot::Canceled;

    #[tokio::test]
    async fn test_spawn_dedicated() {
        let sum = RayonBackend::spawn(compute_sum).await.unwrap();
        assert_eq!(sum, 4950);
    }

    #[derive(thiserror::Error, Debug)]
    enum TestError {
        #[error("")]
        Foo(#[from] Canceled),
    }

    fn compute_sum() -> Result<u32, TestError> {
        Ok((0..100).sum())
    }
}
