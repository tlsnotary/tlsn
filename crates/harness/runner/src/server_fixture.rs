use std::{net::Ipv4Addr, path::PathBuf};

use anyhow::Result;

use crate::network::Namespace;

pub struct ServerFixture {
    path: PathBuf,
    namespace: Namespace,
    addr: (Ipv4Addr, u16),
    handle: Option<duct::Handle>,
}

impl ServerFixture {
    /// Spawns a new server fixture.
    pub fn new(path: PathBuf, namespace: Namespace, addr: (Ipv4Addr, u16)) -> Self {
        Self {
            path,
            namespace,
            addr,
            handle: None,
        }
    }

    /// Starts the server fixture.
    pub fn start(&mut self) -> Result<()> {
        if self.handle.is_some() {
            return Ok(());
        }

        let handle = duct::cmd!(
            "sudo",
            "ip",
            "netns",
            "exec",
            self.namespace.name(),
            "env",
            format!("ADDR={}", self.addr.0),
            format!("PORT={}", self.addr.1),
            &self.path
        )
        .stderr_capture()
        .stdout_capture()
        .start()?;

        self.handle = Some(handle);

        Ok(())
    }

    /// Shuts down the server fixture.
    pub fn shutdown(&self) {
        self.handle.as_ref().inspect(|handle| _ = handle.kill());
    }
}

impl Drop for ServerFixture {
    fn drop(&mut self) {
        self.shutdown();
    }
}
