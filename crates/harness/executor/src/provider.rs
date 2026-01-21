#![allow(unused)]

use std::net::Ipv4Addr;

use harness_core::{IoMode, network::NetworkConfig};

const MAX_RETRIES: usize = 50;
const RETRY_DELAY_MS: usize = 50;

pub struct IoProvider {
    mode: IoMode,
    config: NetworkConfig,
}

impl IoProvider {
    /// Creates a new provider.
    pub(crate) fn new(mode: IoMode, network_config: NetworkConfig) -> Self {
        Self {
            mode,
            config: network_config,
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use super::{IoProvider, MAX_RETRIES, RETRY_DELAY_MS};
    use crate::io::Io;
    use anyhow::Result;
    use harness_core::IoMode;
    use std::{io::ErrorKind, time::Duration};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_util::compat::TokioAsyncReadCompatExt;

    impl IoProvider {
        /// Provides a connection to the server.
        pub async fn provide_server_io(&self) -> Result<impl Io> {
            TcpStream::connect(self.config.app)
                .await
                .inspect(|io| io.set_nodelay(true).unwrap())
                .map(|io| io.compat())
                .map_err(anyhow::Error::from)
        }

        /// Provides a connection to the peer.
        pub async fn provide_proto_io(&self) -> Result<impl Io> {
            match self.mode {
                IoMode::Client => {
                    // It might take a bit for the peer to start up, so we retry a few times.
                    let mut retries = 0;
                    loop {
                        match TcpStream::connect(self.config.proto_1)
                            .await
                            .inspect(|io| io.set_nodelay(true).unwrap())
                            .map(|io| io.compat())
                        {
                            Ok(io) => return Ok(io),
                            Err(e) if e.kind() == ErrorKind::ConnectionRefused => {
                                tokio::time::sleep(Duration::from_millis(RETRY_DELAY_MS as u64))
                                    .await;
                                retries += 1;
                                if retries > MAX_RETRIES {
                                    return Err(e.into());
                                }
                            }
                            Err(e) => return Err(e.into()),
                        }
                    }
                }
                IoMode::Server => {
                    let listener = TcpListener::bind(self.config.proto_1).await?;
                    let (io, _) = listener.accept().await?;
                    io.set_nodelay(true).unwrap();
                    Ok(io.compat())
                }
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use super::IoProvider;
    use crate::io::Io;
    use anyhow::{Result, anyhow};
    use std::time::Duration;

    const CHECK_WS_OPEN_DELAY_MS: usize = 50;
    const MAX_RETRIES: usize = 50;

    impl IoProvider {
        /// Provides a connection to the server.
        pub async fn provide_server_io(&self) -> Result<impl Io> {
            let url = format!(
                "ws://{}:{}/tcp?addr={}%3A{}",
                &self.config.app_proxy.0,
                self.config.app_proxy.1,
                &self.config.app.0,
                self.config.app.1,
            );
            let (_, io) = ws_stream_wasm::WsMeta::connect(url, None).await?;

            Ok(io.into_io())
        }

        /// Provides a connection to the verifier.
        pub async fn provide_proto_io(&self) -> Result<impl Io> {
            let url = format!(
                "ws://{}:{}/tcp?addr={}%3A{}",
                &self.config.proto_proxy.0,
                self.config.proto_proxy.1,
                &self.config.proto_1.0,
                self.config.proto_1.1,
            );
            let mut retries = 0;

            let io = loop {
                // Connect to the websocket relay.
                let (_, io) = ws_stream_wasm::WsMeta::connect(url.clone(), None).await?;

                // Allow some time for the relay to initiate a connection to
                // the verifier.
                std::thread::sleep(Duration::from_millis(CHECK_WS_OPEN_DELAY_MS as u64));

                // If the relay didn't close the io, most likely the verifier
                // accepted the connection.
                if io.ready_state() == ws_stream_wasm::WsState::Open {
                    break io;
                }

                retries += 1;
                if retries > MAX_RETRIES {
                    return Err(anyhow!("verifier did not accept connection"));
                }
            };

            Ok(io.into_io())
        }
    }
}
