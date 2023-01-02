use async_trait::async_trait;

/// This trait is for factories which produce their items asynchronously
#[async_trait]
pub trait AsyncFactory<C, T, E> {
    /// Returns new instance
    ///
    /// * `id` - Unique ID of instance
    /// * `config` - Instance configuration
    async fn new(&mut self, id: String, config: C) -> Result<T, E>;
}
