use futures::task::Spawn;

/// Compatibility trait for implementing `futures::task::Spawn` for executors.
pub trait SpawnCompatExt {
    /// Wrap the executor in a `Compat` wrapper.
    fn compat(self) -> Compat<Self>
    where
        Self: Sized;

    /// Wrap a reference to the executor in a `Compat` wrapper.
    fn compat_ref(&self) -> Compat<&Self>;

    /// Wrap a mutable reference to the executor in a `Compat` wrapper.
    fn compat_mut(&mut self) -> Compat<&mut Self>;
}

impl<T> SpawnCompatExt for T {
    fn compat(self) -> Compat<Self>
    where
        Self: Sized,
    {
        Compat::new(self)
    }

    fn compat_ref(&self) -> Compat<&Self> {
        Compat::new(self)
    }

    fn compat_mut(&mut self) -> Compat<&mut Self> {
        Compat::new(self)
    }
}

pub struct Compat<T>(T);

impl<T> Compat<T> {
    /// Create a new `Compat` wrapper around `inner`.
    pub fn new(inner: T) -> Self {
        Self(inner)
    }
}

#[cfg(feature = "tokio_compat")]
impl Spawn for Compat<tokio::runtime::Runtime> {
    fn spawn_obj(
        &self,
        future: futures::future::FutureObj<'static, ()>,
    ) -> Result<(), futures::task::SpawnError> {
        drop(self.0.spawn(future));
        Ok(())
    }
}

#[cfg(feature = "tokio_compat")]
impl Spawn for Compat<tokio::runtime::Handle> {
    fn spawn_obj(
        &self,
        future: futures::future::FutureObj<'static, ()>,
    ) -> Result<(), futures::task::SpawnError> {
        drop(self.0.spawn(future));
        Ok(())
    }
}

#[cfg(feature = "wasm_compat")]
#[derive(Debug, Clone, Copy)]
pub struct WasmBindgenExecutor;

#[cfg(feature = "wasm_compat")]
impl Spawn for WasmBindgenExecutor {
    fn spawn_obj(
        &self,
        future: futures::future::FutureObj<'static, ()>,
    ) -> Result<(), futures::task::SpawnError> {
        wasm_bindgen_futures::spawn_local(future);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use futures::task::SpawnExt;

    async fn foo(exec: &impl Spawn) {
        let task = exec.spawn_with_handle(async {}).unwrap();
        task.await
    }

    #[tokio::test]
    async fn test_tokio_compat() {
        foo(&tokio::runtime::Handle::current().compat()).await;
    }
}
