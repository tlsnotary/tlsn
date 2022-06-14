use futures::{AsyncRead, AsyncWrite};

pub struct ConnectionSlave<S> {
    master_conn: S,
}

impl<S> ConnectionSlave<S>
where
    S: AsyncWrite + AsyncRead,
{
    pub fn new() -> Self {
        todo!()
    }
}
