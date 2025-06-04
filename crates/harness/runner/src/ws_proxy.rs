use std::net::Ipv4Addr;

use anyhow::Result;
use tokio::net::TcpListener;

pub struct WsProxy {
    addr: (Ipv4Addr, u16),
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl WsProxy {
    /// Spawns a new ws proxy.
    pub fn new(addr: (Ipv4Addr, u16)) -> Self {
        Self { addr, handle: None }
    }

    /// Starts the ws proxy.
    pub async fn start(&mut self) -> Result<()> {
        let listener = TcpListener::bind(self.addr).await?;
        let handle = tokio::spawn(async move {
            websocket_relay::run(listener).await.unwrap();
        });

        self.handle = Some(handle);

        Ok(())
    }

    /// Shuts down the ws proxy.
    pub fn shutdown(&self) {
        self.handle.as_ref().inspect(|handle| _ = handle.abort());
    }
}

impl Drop for WsProxy {
    fn drop(&mut self) {
        self.shutdown();
    }
}
