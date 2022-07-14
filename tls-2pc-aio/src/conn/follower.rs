use futures::{AsyncRead, AsyncWrite};

pub struct ConnectionFollower<S> {
    master_conn: S,
}

impl<S> ConnectionFollower<S>
where
    S: AsyncWrite + AsyncRead,
{
    pub fn new() -> Self {
        todo!()
    }
}
