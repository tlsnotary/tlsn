#![allow(unused)]

use std::net::Ipv4Addr;

use anyhow::{Result, bail};
use futures::{AsyncReadExt, AsyncWriteExt};
use harness_core::{IoMode, network::NetworkConfig};

use crate::io::Io;

const MAX_RETRIES: usize = 50;
const RETRY_DELAY_MS: usize = 50;

/// Deadline for a native protocol-connection handshake. Keeps a half-open
/// connection (one accepted into the listener backlog while the peer app
/// never reaches `provide_proto_io`) from stalling setup indefinitely.
const CONNECT_HANDSHAKE_TIMEOUT_MS: u64 = 2000;

/// Magic byte exchanged in both directions by the protocol peers on connect.
/// See [`connect_handshake`].
const CONNECT_SENTINEL: u8 = 0x51;

/// Symmetric handshake for the prover<->verifier ("protocol") connection.
///
/// Both peers write the sentinel and then read and verify the peer's. A
/// one-way confirmation (listener writes, dialer reads) is enough to close
/// the original ambiguity, but it hard-codes which side listens and which
/// dials. A byte *from* the peer proves the whole path is live -- a bare
/// `connect()` can sit in a listener's backlog before the peer app accepts,
/// and a wasm peer's WS<->TCP relay completes the WS handshake before it has
/// even attempted its downstream dial -- and doing it in both directions
/// keeps the handshake independent of prover/verifier role and of the
/// native/wasm transport, so the two halves can never drift apart.
///
/// Both peers write before reading, so neither can stall a peer that is
/// itself waiting to write first. Callers run this from `provide_proto_io`,
/// before the stream is wrapped for metering and before any bench timer
/// starts, so it does not affect measured results.
async fn connect_handshake<I: Io>(mut io: I) -> Result<I> {
    io.write_all(&[CONNECT_SENTINEL]).await?;
    io.flush().await?;

    let mut peer = [0u8; 1];
    io.read_exact(&mut peer).await?;
    if peer[0] != CONNECT_SENTINEL {
        bail!(
            "unexpected protocol connect handshake byte: {:#04x}",
            peer[0]
        );
    }
    Ok(io)
}

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
    use super::{
        CONNECT_HANDSHAKE_TIMEOUT_MS, IoProvider, MAX_RETRIES, RETRY_DELAY_MS, connect_handshake,
    };
    use crate::io::Io;
    use anyhow::Result;
    use harness_core::IoMode;
    use std::{io::ErrorKind, time::Duration};
    use tokio::{
        net::{TcpListener, TcpStream},
        time::timeout,
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
            let handshake_timeout = Duration::from_millis(CONNECT_HANDSHAKE_TIMEOUT_MS);
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
                            Ok(io) => {
                                return timeout(handshake_timeout, connect_handshake(io))
                                    .await
                                    .map_err(|_| {
                                        anyhow::anyhow!("protocol connect handshake timed out")
                                    })?;
                            }
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
                    timeout(handshake_timeout, connect_handshake(io.compat()))
                        .await
                        .map_err(|_| anyhow::anyhow!("protocol connect handshake timed out"))?
                }
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use super::{CONNECT_SENTINEL, IoProvider, connect_handshake};
    use crate::io::Io;
    use anyhow::{Result, anyhow};
    use js_sys::Uint8Array;
    use std::time::Duration;
    use wasm_bindgen::prelude::*;
    use wasm_bindgen_futures::JsFuture;
    use web_time::Instant;

    const CONNECT_TIMEOUT_MS: u64 = 2000;
    const RETRY_BACKOFF_MS: usize = 20;

    #[wasm_bindgen]
    extern "C" {
        type JsIoChannel;

        #[wasm_bindgen(js_namespace = globalThis, js_name = connectIoChannel)]
        fn connect_io_channel(url: String) -> js_sys::Promise;

        #[wasm_bindgen(method, catch)]
        fn read(this: &JsIoChannel) -> Result<js_sys::Promise, JsValue>;

        #[wasm_bindgen(method, catch)]
        fn write(this: &JsIoChannel, data: &Uint8Array) -> Result<js_sys::Promise, JsValue>;

        /// Pushes bytes back onto the front of the channel's read queue so the
        /// next reader observes them.
        #[wasm_bindgen(method, catch)]
        fn unread(this: &JsIoChannel, data: &Uint8Array) -> Result<(), JsValue>;
    }

    async fn connect_js_io(url: String) -> Result<JsValue> {
        JsFuture::from(connect_io_channel(url))
            .await
            .map_err(|error| anyhow!("failed to connect JS IO: {error:?}"))
    }

    /// Symmetric sentinel handshake over a JavaScript `IoChannel`, mirroring
    /// [`connect_handshake`].
    ///
    /// The JS channel delivers whole WebSocket messages, so any bytes the peer
    /// sent after its sentinel are pushed back for the session to consume.
    async fn connect_js_handshake(io: &JsValue) -> Result<()> {
        let channel = io.unchecked_ref::<JsIoChannel>();

        let promise = channel
            .write(&Uint8Array::from(&[CONNECT_SENTINEL][..]))
            .map_err(|e| anyhow!("failed to write connect sentinel: {e:?}"))?;
        JsFuture::from(promise)
            .await
            .map_err(|e| anyhow!("failed to write connect sentinel: {e:?}"))?;

        let promise = channel
            .read()
            .map_err(|e| anyhow!("failed to read connect sentinel: {e:?}"))?;
        let value = JsFuture::from(promise)
            .await
            .map_err(|e| anyhow!("failed to read connect sentinel: {e:?}"))?;

        let bytes = if value.is_null() || value.is_undefined() {
            Vec::new()
        } else {
            Uint8Array::new(&value).to_vec()
        };

        if bytes.first() != Some(&CONNECT_SENTINEL) {
            return Err(anyhow!("unexpected protocol connect handshake byte"));
        }

        if bytes.len() > 1 {
            channel
                .unread(&Uint8Array::from(&bytes[1..]))
                .map_err(|e| anyhow!("failed to buffer handshake remainder: {e:?}"))?;
        }

        Ok(())
    }

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

        /// Provides a JavaScript `IoChannel` backed by a real WebSocket.
        pub async fn provide_server_js_io(&self) -> Result<JsValue> {
            connect_js_io(format!(
                "ws://{}:{}/tcp?addr={}%3A{}",
                &self.config.app_proxy.0,
                self.config.app_proxy.1,
                &self.config.app.0,
                self.config.app.1,
            ))
            .await
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
                let io = ws.into_io();

                // The symmetric handshake writes our sentinel (forwarded to
                // the verifier) and waits for the verifier's, which the relay
                // forwards through transparently. If the relay's downstream
                // connect instead fails, it closes this WS and the read
                // errors out, so we retry.
                match connect_handshake(io).await {
                    Ok(io) => break io,
                    Err(_) => {
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

        /// Provides a JavaScript `IoChannel` backed by the protocol WebSocket.
        pub async fn provide_proto_js_io(&self) -> Result<JsValue> {
            let url = format!(
                "ws://{}:{}/tcp?addr={}%3A{}",
                &self.config.proto_proxy.0,
                self.config.proto_proxy.1,
                &self.config.proto_1.0,
                self.config.proto_1.1,
            );
            let deadline = Instant::now() + Duration::from_millis(CONNECT_TIMEOUT_MS);

            loop {
                let io = connect_js_io(url.clone()).await?;

                // The relay completes the WS handshake before it has even
                // attempted its downstream connect, so wait for the verifier's
                // sentinel to prove the full path is live.
                match connect_js_handshake(&io).await {
                    Ok(()) => return Ok(io),
                    Err(_) => {
                        if Instant::now() >= deadline {
                            return Err(anyhow!(
                                "verifier did not accept connection within {CONNECT_TIMEOUT_MS}ms"
                            ));
                        }
                        std::thread::sleep(Duration::from_millis(RETRY_BACKOFF_MS as u64));
                    }
                }
            }
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::connect_handshake;
    use futures::{AsyncReadExt, AsyncWriteExt};
    use tokio_util::compat::TokioAsyncReadCompatExt;

    #[tokio::test]
    async fn connect_handshake_is_symmetric_and_byte_clean() {
        let (a, b) = tokio::io::duplex(64);
        let (a, b) = (a.compat(), b.compat());

        // Both peers run the identical handshake concurrently, as in a real
        // session. Each writes before reading, so neither waits on the other.
        let (a, b) = futures::join!(connect_handshake(a), connect_handshake(b));
        let (mut a, mut b) = (a.unwrap(), b.unwrap());

        // The handshake must consume exactly the sentinel bytes and leave
        // nothing behind: a normal message passes through intact.
        a.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
    }
}
