use bytes::BytesMut;
use prost::Message;
use std::marker::PhantomData;
use tokio_util::codec::{Decoder, Encoder, LengthDelimitedCodec};

#[derive(Debug, Clone)]
pub struct ProstCodec<T, U>(PhantomData<T>, PhantomData<U>);

impl<T, U: Message> Default for ProstCodec<T, U> {
    fn default() -> Self {
        ProstCodec(PhantomData, PhantomData)
    }
}

impl<T, U: Message + From<T>> Encoder<T> for ProstCodec<T, U> {
    type Error = std::io::Error;

    fn encode(&mut self, item: T, buf: &mut BytesMut) -> Result<(), Self::Error> {
        U::from(item)
            .encode(buf)
            .expect("Message only errors if not enough space");

        Ok(())
    }
}

impl<T: TryFrom<U>, U: Message + Default> Decoder for ProstCodec<T, U>
where
    std::io::Error: From<<T as TryFrom<U>>::Error>,
{
    type Item = T;
    type Error = std::io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let item: U = Message::decode(buf)?;

        Ok(Some(T::try_from(item)?))
    }
}

#[derive(Debug, Clone)]
pub struct ProstCodecDelimited<T, U> {
    _t: (PhantomData<T>, PhantomData<U>),
    inner: LengthDelimitedCodec,
}

impl<T, U: Message> Default for ProstCodecDelimited<T, U> {
    fn default() -> Self {
        ProstCodecDelimited {
            _t: (PhantomData, PhantomData),
            inner: LengthDelimitedCodec::new(),
        }
    }
}

impl<T, U: Message + From<T>> Encoder<T> for ProstCodecDelimited<T, U> {
    type Error = std::io::Error;

    fn encode(&mut self, item: T, buf: &mut BytesMut) -> Result<(), Self::Error> {
        self.inner.encode(U::from(item).encode_to_vec().into(), buf)
    }
}

impl<T: TryFrom<U>, U: Message + Default> Decoder for ProstCodecDelimited<T, U>
where
    std::io::Error: From<<T as TryFrom<U>>::Error>,
{
    type Item = T;
    type Error = std::io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let b = self.inner.decode(buf)?;
        if let Some(b) = b {
            let item: U = Message::decode(b)?;
            return Ok(Some(T::try_from(item)?));
        } else {
            return Ok(None);
        }
    }
}
