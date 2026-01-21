use std::{net::Ipv4Addr, path::PathBuf};

use anyhow::Result;

use crate::network::Namespace;

pub struct WsProxy {
    namespace: Namespace,
    path: PathBuf,
    addr: (Ipv4Addr, u16),
    handle: Option<duct::Handle>,
}

impl WsProxy {
    /// Creates a new ws proxy.
    pub fn new(namespace: Namespace, path: PathBuf, addr: (Ipv4Addr, u16)) -> Self {
        Self {
            namespace,
            path,
            addr,
            handle: None,
        }
    }

    /// Starts the ws proxy.
    pub fn start(&mut self) -> Result<()> {
        let handle = duct::cmd!(
            "sudo",
            "ip",
            "netns",
            "exec",
            &self.namespace.name(),
            "env",
            format!("PROXY_IP={}", self.addr.0),
            format!("PROXY_PORT={}", self.addr.1),
            &self.path,
        )
        .stderr_capture()
        .stdout_capture()
        .start()?;

        self.handle = Some(handle);

        Ok(())
    }

    /// Shuts down the ws proxy.
    pub fn shutdown(&self) {
        self.handle.as_ref().inspect(|handle| {
            _ = handle.kill();
        });
    }
}

impl Drop for WsProxy {
    fn drop(&mut self) {
        self.shutdown();
    }
}
