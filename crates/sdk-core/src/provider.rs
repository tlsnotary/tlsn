use std::pin::Pin;

use futures::{AsyncRead, AsyncWrite};
use tlsn::connection::ServerName;

pub trait IoProvider {
    type Io: AsyncRead + AsyncWrite + Send + Unpin + 'static;
    type Error: std::error::Error + Send + Sync + 'static;

    fn connect_server(
        &mut self,
        name: &ServerName,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Io, Self::Error>> + Send>>;

    fn connect_peer(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Io, Self::Error>> + Send>>;
}
