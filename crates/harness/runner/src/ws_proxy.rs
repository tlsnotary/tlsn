use std::net::{IpAddr, Ipv4Addr};

use anyhow::Result;
use tokio::net::TcpListener;
use websocket_relay::Relay;

pub struct WsProxy {
    addr: (Ipv4Addr, u16),
    local_address: Option<IpAddr>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl WsProxy {
    /// Spawns a new ws proxy.
    pub fn new(addr: (Ipv4Addr, u16)) -> Self {
        Self {
            addr,
            local_address: None,
            handle: None,
        }
    }

    /// Sets the local address to bind to when connecting to the target.
    ///
    /// This is used to ensure that the target responds to the correct IP
    /// address, which is important for proper latency emulation.
    pub fn local_address(mut self, addr: IpAddr) -> Self {
        self.local_address = Some(addr);
        self
    }

    /// Starts the ws proxy.
    pub async fn start(&mut self) -> Result<()> {
        let listener = TcpListener::bind(self.addr).await?;

        let mut builder = Relay::builder();
        if let Some(local_addr) = self.local_address {
            builder = builder.local_address(local_addr);
        }
        let relay = builder.build();

        let handle = tokio::spawn(async move {
            relay.run(listener).await.unwrap();
        });

        self.handle = Some(handle);

        Ok(())
    }

    /// Shuts down the ws proxy.
    pub fn shutdown(&self) {
        self.handle.as_ref().inspect(|handle| handle.abort());
    }
}

impl Drop for WsProxy {
    fn drop(&mut self) {
        self.shutdown();
    }
}
