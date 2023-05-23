use async_trait::async_trait;
use futures::channel::oneshot;

pub type Backend = RayonBackend;

/// Allows to spawn a closure on a thread outside of the async runtime
///
/// This allows to perform CPU-intensive tasks without blocking the runtime.
#[async_trait]
pub trait NonBlockingBackend {
    /// Spawn the closure in a separate thread and await the result
    async fn spawn<F: FnOnce() -> T + Send + 'static, T: Send + 'static>(closure: F) -> T;
}

/// A CPU backend that uses Rayon
pub struct RayonBackend;

#[async_trait]
impl NonBlockingBackend for RayonBackend {
    async fn spawn<F: FnOnce() -> T + Send + 'static, T: Send + 'static>(closure: F) -> T {
        let (sender, receiver) = oneshot::channel();
        rayon::spawn(move || {
            _ = sender.send(closure());
        });

        receiver.await.expect("channel should not be canceled")
    }
}

#[cfg(test)]
mod tests {
    use super::{Backend, NonBlockingBackend};

    #[tokio::test]
    async fn test_spawn() {
        let sum = Backend::spawn(compute_sum).await;
        assert_eq!(sum, 4950);
    }

    fn compute_sum() -> u32 {
        (0..100).sum()
    }
}
