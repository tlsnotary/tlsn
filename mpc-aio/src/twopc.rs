use async_trait::async_trait;
use futures_util::{Sink, Stream};

#[async_trait]
pub trait TwoPCProtocol<T> {
    type Input;
    type Output;

    async fn run<S: Sink<T> + Stream<Item = Result<T, E>> + Send + Unpin, E: std::fmt::Debug>(
        &mut self,
        stream: &mut S,
        input: Self::Input,
    ) -> Self::Output
    where
        <S as Sink<T>>::Error: std::fmt::Debug;
}
