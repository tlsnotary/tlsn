use async_trait::async_trait;

/// This trait is for factories which produce their items asynchronously
#[async_trait]
pub trait AsyncFactory<T> {
    type Config;
    type Error;

    /// Creates new instance
    ///
    /// * `id` - Unique ID of instance
    /// * `config` - Instance configuration
    async fn create(&mut self, id: String, config: Self::Config) -> Result<T, Self::Error>;
}
