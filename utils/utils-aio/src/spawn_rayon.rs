use async_trait::async_trait;
use futures::channel::{oneshot, oneshot::Canceled};

/// Allows to spawn a closure on a thread of the rayon threadpool
///
/// This allows to perform CPU-intensive tasks without blocking a thread of the async runtime.
#[async_trait]
pub trait SpawnRayon<T: Send + 'static> {
    type Error: std::error::Error + From<Canceled>;

    // Spawn the closure in a separate thread and await the result
    async fn spawn<
        F: FnOnce() -> Result<T, R> + Send + 'static,
        R: std::error::Error + Into<Self::Error> + Send + 'static,
    >(
        closure: F,
    ) -> Result<T, Self::Error> {
        let (sender, receiver) = oneshot::channel();
        rayon::spawn(move || {
            _ = sender.send(closure());
        });

        receiver.await?.map_err(Into::into)
    }
}
