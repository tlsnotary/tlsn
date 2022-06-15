use futures::{AsyncRead, AsyncWrite};

/// HandshakeSlave communicates with [`HandshakeMaster`] over a stream to execute TLS operations in 2PC
pub struct HandshakeSlave<S> {
    /// Stream connection to [`HandshakeSlave`]
    stream: S,
}

impl<S> HandshakeSlave<S>
where
    S: AsyncWrite + AsyncRead + Send,
{
    pub fn new(stream: S) -> Self {
        Self { stream }
    }

    /// Perform setup for 2PC sub-protocols
    pub async fn setup(&mut self) {
        todo!()
    }

    /// Receives and processes messages from Master over stream
    pub async fn run(&mut self) {
        todo!()
    }
}
