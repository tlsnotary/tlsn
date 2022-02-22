pub mod errors;

use async_trait::async_trait;
use errors::*;
use pop_mpc_core::ot::{OTReceiver, OTSender};
use tokio::io::{self, AsyncRead, AsyncWrite};
use tokio::net::UnixStream;

pub struct UnixOTSender<OT> {
    ot: OT,
    io: UnixStream,
}

pub struct UnixOTReceiver<OT> {
    ot: OT,
    io: UnixStream,
}

#[async_trait]
pub trait AsyncOTSender {
    async fn send() -> Result<(), AsyncOTSenderError>;
}

#[async_trait]
pub trait AsyncOTReceiver {
    async fn receive(&mut self) -> Result<(), AsyncOTReceiverError>;
}

impl<OT: OTSender> UnixOTSender<OT> {
    pub fn new(ot: OT, io: UnixStream) -> Self {
        Self { ot, io }
    }
}

#[async_trait]
impl<OT: OTSender> AsyncOTSender for UnixOTSender<OT> {
    async fn send() -> Result<(), AsyncOTSenderError> {
        Ok(())
    }
}

impl<OT: OTReceiver> UnixOTReceiver<OT> {
    pub fn new(ot: OT, io: UnixStream) -> Self {
        Self { ot, io }
    }
}

#[async_trait]
impl<OT: OTReceiver> AsyncOTReceiver for UnixOTReceiver<OT> {
    async fn receive(&mut self) -> Result<(), AsyncOTReceiverError> {
        let base_setup = self.ot.base_setup()?;
        let r = self.io.try_write(base_setup.as_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pop_mpc_core::ot::{ChaChaAesOTReceiver, ChaChaAesOTSender};
    use tokio::net::UnixStream;

    #[test]
    fn test_async_ot() {
        let (unix_s, unix_r) = UnixStream::pair().unwrap();
        let s_ot = ChaChaAesOTSender::default();
        let r_ot = ChaChaAesOTReceiver::default();
        let s = UnixOTSender::new(s_ot, unix_s);
        let r = UnixOTReceiver::new(r_ot, unix_r);
    }
}
