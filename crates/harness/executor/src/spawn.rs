use anyhow::Context;

/// Spawns a future.
pub fn spawn<F>(f: F) -> impl Future<Output = anyhow::Result<F::Output>> + Send
where
    F: Future + Send + 'static,
    F::Output: Send,
{
    #[cfg(target_arch = "wasm32")]
    {
        let (sender, receiver) = futures::channel::oneshot::channel();
        wasm_bindgen_futures::spawn_local(async move {
            _ = sender.send(f.await);
        });

        async move { receiver.await.context("future result was dropped") }
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            _ = sender.send(f.await);
        });

        async move { receiver.await.context("future result was dropped") }
    }
}
