#![allow(unused)]

use std::net::Ipv4Addr;

use harness_core::{IoMode, network::NetworkConfig};

const MAX_RETRIES: usize = 50;
const RETRY_DELAY_MS: usize = 50;

/// Byte the verifier writes immediately after accepting a genuine protocol
/// connection. On wasm, the prover connects through a WS<->TCP relay that
/// completes the WS handshake with the prover before it has even attempted
/// its downstream TCP connect to the verifier, so an open WS alone does not
/// mean the verifier accepted anything. Waiting for this sentinel (which the
/// relay forwards through transparently once written) gives the prover a
/// real confirmation instead of guessing based on elapsed time.
const CONNECT_SENTINEL: u8 = 0x51;

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
    use super::{CONNECT_SENTINEL, IoProvider, MAX_RETRIES, RETRY_DELAY_MS};
    use crate::io::Io;
    use anyhow::Result;
    use harness_core::IoMode;
    use std::{io::ErrorKind, time::Duration};
    use tokio::{
        io::AsyncWriteExt,
        net::{TcpListener, TcpStream},
    };
    use tokio_util::compat::TokioAsyncReadCompatExt;

    impl IoProvider {
        /// Provides a connection to the server.
        pub async fn provide_server_io(&self) -> Result<impl Io> {
            TcpStream::connect(self.config.app)
                .await
                .map(|io| io.compat())
                .map_err(anyhow::Error::from)
        }

        /// Provides a connection to the peer.
        pub async fn provide_proto_io(&self) -> Result<impl Io> {
            match self.mode {
                IoMode::Client => {
                    // It might take a bit for the peer to start up, so we retry
                    // a few times.
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
                    let (mut io, _) = listener.accept().await?;
                    io.set_nodelay(true).unwrap();
                    // Confirm to the peer that this is a genuine connection
                    // (see CONNECT_SENTINEL doc comment).
                    io.write_all(&[CONNECT_SENTINEL]).await?;
                    Ok(io.compat())
                }
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use super::{CONNECT_SENTINEL, IoProvider};
    use crate::io::Io;
    use anyhow::{Result, anyhow};
    use futures::AsyncReadExt;
    use std::time::Duration;
    use web_time::Instant;

    const CONNECT_TIMEOUT_MS: u64 = 2000;
    const RETRY_BACKOFF_MS: usize = 20;

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
            let deadline = Instant::now() + Duration::from_millis(CONNECT_TIMEOUT_MS);

            let io = loop {
                // Connect to the websocket relay. Note this only confirms a
                // WS handshake with the relay itself: the relay completes
                // this handshake before it has even attempted its
                // downstream TCP connect to the verifier, so it is not a
                // signal that the verifier is reachable.
                let (_, ws) = ws_stream_wasm::WsMeta::connect(url.clone(), None).await?;
                let mut io = ws.into_io();

                // Wait for the verifier's connect sentinel, which the relay
                // forwards through transparently once written. If the
                // relay's downstream connect instead fails, it closes this
                // WS and the read below errors out.
                let mut sentinel = [0u8; 1];
                match io.read_exact(&mut sentinel).await {
                    Ok(()) if sentinel[0] == CONNECT_SENTINEL => break io,
                    _ => {
                        if Instant::now() >= deadline {
                            return Err(anyhow!(
                                "verifier did not accept connection within {CONNECT_TIMEOUT_MS}ms"
                            ));
                        }
                        // Cool down before retrying, so a verifier that's
                        // slow to come up isn't bombarded with reconnect
                        // attempts in a tight loop.
                        std::thread::sleep(Duration::from_millis(RETRY_BACKOFF_MS as u64));
                    }
                }
            };

            Ok(io)
        }
    }
}
