use async_trait::async_trait;
use futures_util::{AsyncRead, AsyncWrite};
use tokio_serde::formats::Bincode;
use tokio_util::{codec::LengthDelimitedCodec, compat::FuturesAsyncReadCompatExt};

use crate::{
    mux::{MuxChannelSerde, MuxStream, MuxerError},
    Channel,
};

/// Wraps a [`MuxStream`] and provides a [`Channel`] with a bincode codec
#[derive(Debug, Clone)]
pub struct BincodeMux<M>(M);

impl<M> BincodeMux<M>
where
    M: MuxStream,
{
    /// Creates a new bincode mux
    pub fn new(mux: M) -> Self {
        Self(mux)
    }

    /// Attaches a bincode codec to the provided stream
    pub fn attach_codec<S: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static, T>(
        &self,
        stream: S,
    ) -> impl Channel<T>
    where
        T: serde::Serialize + for<'a> serde::Deserialize<'a> + Send + Sync + Unpin + 'static,
    {
        let framed = LengthDelimitedCodec::builder().new_framed(stream.compat());

        tokio_serde::Framed::new(framed, Bincode::default())
    }
}

#[async_trait]
impl<M> MuxChannelSerde for BincodeMux<M>
where
    M: MuxStream + Send + 'static,
{
    async fn get_channel<
        T: serde::Serialize + serde::de::DeserializeOwned + Send + Sync + Unpin + 'static,
    >(
        &mut self,
        id: &str,
    ) -> Result<Box<dyn Channel<T> + 'static>, MuxerError> {
        let stream = self.0.get_stream(id).await?;

        Ok(Box::new(self.attach_codec(stream)))
    }
}

#[cfg(test)]
mod tests {
    use crate::mux::mock::MockMuxChannelFactory;

    use super::*;

    use futures::{SinkExt, StreamExt};

    #[derive(serde::Serialize, serde::Deserialize)]
    struct Foo {
        msg: String,
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    struct Bar {
        msg: String,
    }

    #[tokio::test]
    async fn test_mux_codec() {
        let mux = MockMuxChannelFactory::new();

        let mut framed_mux = BincodeMux::new(mux);

        let mut channel_0 = framed_mux.get_channel("foo").await.unwrap();
        let mut channel_1 = framed_mux.get_channel("foo").await.unwrap();

        channel_0
            .send(Foo {
                msg: "hello".to_string(),
            })
            .await
            .unwrap();

        let msg: Foo = channel_1.next().await.unwrap().unwrap();

        assert_eq!(msg.msg, "hello");

        let mut channel_0 = framed_mux.get_channel("bar").await.unwrap();
        let mut channel_1 = framed_mux.get_channel("bar").await.unwrap();

        channel_0
            .send(Bar {
                msg: "world".to_string(),
            })
            .await
            .unwrap();

        let msg: Bar = channel_1.next().await.unwrap().unwrap();

        assert_eq!(msg.msg, "world");
    }
}
