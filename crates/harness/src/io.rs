use futures::{AsyncRead, AsyncWrite};

pub trait Io: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

impl<T> Io for T where T: AsyncRead + AsyncWrite + Send + Unpin + 'static {}
