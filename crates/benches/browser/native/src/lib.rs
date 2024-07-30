//! Contains the native component of the browser prover.
//!
//! Conceptually the browser prover consists of the native and the wasm components. The native
//! component is responsible for starting the browser, loading the wasm component and driving it.

use std::{env, net::IpAddr};

use serio::{stream::IoStreamExt, SinkExt as _};
use tlsn_benches_browser_core::{
    msg::{Config, Runtime},
    FramedIo,
};
use tlsn_benches_library::{AsyncIo, ProverTrait};

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use chromiumoxide::{
    cdp::{
        browser_protocol::log::{EventEntryAdded, LogEntryLevel},
        js_protocol::runtime::EventExceptionThrown,
    },
    Browser, BrowserConfig, Page,
};
use futures::{Future, FutureExt, StreamExt};
use rust_embed::RustEmbed;
use tokio::{io, io::AsyncWriteExt, net::TcpListener, task::JoinHandle};
use tracing::{debug, error};
use warp::Filter;

/// The IP on which the wasm component is served.
pub static DEFAULT_WASM_IP: &str = "127.0.0.1";
/// The IP of the websocket relay.
pub static DEFAULT_WS_IP: &str = "127.0.0.1";

/// The port on which the wasm component is served.
pub static DEFAULT_WASM_PORT: u16 = 9001;
/// The port of the websocket relay.
pub static DEFAULT_WS_PORT: u16 = 9002;
/// The port for the wasm component to communicate with the TLS server.
pub static DEFAULT_WASM_TO_SERVER_PORT: u16 = 9003;
/// The port for the wasm component to communicate with the verifier.
pub static DEFAULT_WASM_TO_VERIFIER_PORT: u16 = 9004;
/// The port for the wasm component to communicate with the native component.
pub static DEFAULT_WASM_TO_NATIVE_PORT: u16 = 9005;

// The `pkg` dir will be embedded into the binary at compile-time.
#[derive(RustEmbed)]
#[folder = "../wasm/pkg"]
struct Data;

/// The native component of the prover which runs in the browser.
pub struct BrowserProver {
    /// Io for communication with the wasm component.
    wasm_io: FramedIo,
    /// The browser spawned by the prover.
    browser: Browser,
    /// A handle to the http server.
    http_server: JoinHandle<()>,
    /// Handles to the relays.
    relays: Vec<JoinHandle<Result<(), anyhow::Error>>>,
}

#[async_trait]
impl ProverTrait for BrowserProver {
    async fn setup(
        upload_size: usize,
        download_size: usize,
        defer_decryption: bool,
        verifier_io: Box<dyn AsyncIo>,
        server_io: Box<dyn AsyncIo>,
    ) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        let wasm_port: u16 = env::var("WASM_PORT")
            .map(|port| port.parse().expect("port should be valid integer"))
            .unwrap_or(DEFAULT_WASM_PORT);
        let ws_port: u16 = env::var("WS_PORT")
            .map(|port| port.parse().expect("port should be valid integer"))
            .unwrap_or(DEFAULT_WS_PORT);
        let wasm_to_server_port: u16 = env::var("WASM_TO_SERVER_PORT")
            .map(|port| port.parse().expect("port should be valid integer"))
            .unwrap_or(DEFAULT_WASM_TO_SERVER_PORT);
        let wasm_to_verifier_port: u16 = env::var("WASM_TO_VERIFIER_PORT")
            .map(|port| port.parse().expect("port should be valid integer"))
            .unwrap_or(DEFAULT_WASM_TO_VERIFIER_PORT);
        let wasm_to_native_port: u16 = env::var("WASM_TO_NATIVE_PORT")
            .map(|port| port.parse().expect("port should be valid integer"))
            .unwrap_or(DEFAULT_WASM_TO_NATIVE_PORT);

        let wasm_ip: IpAddr = env::var("WASM_IP")
            .map(|addr| addr.parse().expect("should be valid IP address"))
            .unwrap_or(IpAddr::V4(DEFAULT_WASM_IP.parse().unwrap()));
        let ws_ip: IpAddr = env::var("WS_IP")
            .map(|addr| addr.parse().expect("should be valid IP address"))
            .unwrap_or(IpAddr::V4(DEFAULT_WS_IP.parse().unwrap()));

        let mut relays = Vec::with_capacity(4);

        relays.push(spawn_websocket_relay(ws_ip, ws_port).await?);

        let http_server = spawn_http_server(wasm_ip, wasm_port)?;

        // Relay data from the wasm component to the server.
        relays.push(spawn_port_relay(wasm_to_server_port, server_io).await?);

        // Relay data from the wasm component to the verifier.
        relays.push(spawn_port_relay(wasm_to_verifier_port, verifier_io).await?);

        // Create a framed connection to the wasm component.
        let (wasm_left, wasm_right) = tokio::io::duplex(1 << 16);
        relays.push(spawn_port_relay(wasm_to_native_port, Box::new(wasm_right)).await?);
        let mut wasm_io = FramedIo::new(Box::new(wasm_left));

        // Note that the browser must be spawned only when the WebSocket relay is running.
        let browser = spawn_browser(
            wasm_ip,
            ws_ip,
            wasm_port,
            ws_port,
            wasm_to_server_port,
            wasm_to_verifier_port,
            wasm_to_native_port,
        )
        .await?;

        wasm_io
            .send(Config {
                upload_size,
                download_size,
                defer_decryption,
            })
            .await?;

        Ok(Self {
            wasm_io,
            browser,
            http_server,
            relays,
        })
    }

    async fn run(&mut self) -> anyhow::Result<u64> {
        let runtime: Runtime = self.wasm_io.expect_next().await.unwrap();

        _ = self.clean_up().await?;

        Ok(runtime.0)
    }
}

impl BrowserProver {
    async fn clean_up(&mut self) -> anyhow::Result<()> {
        // Kill the http server.
        self.http_server.abort();

        // Kill all relays.
        let _ = self
            .relays
            .iter_mut()
            .map(|task| task.abort())
            .collect::<Vec<_>>();

        // Close the browser.
        self.browser.close().await?;
        self.browser.wait().await?;

        Ok(())
    }
}

pub async fn spawn_websocket_relay(
    ip: IpAddr,
    port: u16,
) -> anyhow::Result<JoinHandle<Result<(), anyhow::Error>>> {
    let listener = TcpListener::bind((ip, port)).await?;
    Ok(tokio::spawn(websocket_relay::run(listener)))
}

/// Binds to the given localhost `port`, accepts a connection and relays data between the
/// connection and the `channel`.
pub async fn spawn_port_relay(
    port: u16,
    channel: Box<dyn AsyncIo>,
) -> anyhow::Result<JoinHandle<Result<(), anyhow::Error>>> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .context("failed to bind to port")?;

    let handle = tokio::spawn(async move {
        let (tcp, _) = listener
            .accept()
            .await
            .context("failed to accept a connection")
            .unwrap();

        relay_data(Box::new(tcp), channel).await
    });

    Ok(handle)
}

/// Relays data between two sources.
pub async fn relay_data(left: Box<dyn AsyncIo>, right: Box<dyn AsyncIo>) -> Result<()> {
    let (mut left_read, mut left_write) = io::split(left);
    let (mut right_read, mut right_write) = io::split(right);

    let left_to_right = async {
        io::copy(&mut left_read, &mut right_write).await?;
        right_write.shutdown().await
    };

    let right_to_left = async {
        io::copy(&mut right_read, &mut left_write).await?;
        left_write.shutdown().await
    };

    tokio::try_join!(left_to_right, right_to_left)?;

    Ok(())
}

/// Spawns the browser and starts the wasm component.
async fn spawn_browser(
    wasm_ip: IpAddr,
    ws_ip: IpAddr,
    wasm_port: u16,
    ws_port: u16,
    wasm_to_server_port: u16,
    wasm_to_verifier_port: u16,
    wasm_to_native_port: u16,
) -> anyhow::Result<Browser> {
    // Chrome requires --no-sandbox when running as root.
    let config = BrowserConfig::builder()
        .no_sandbox()
        .build()
        .map_err(|s| anyhow!(s))?;

    debug!("launching chromedriver");

    let (browser, mut handler) = Browser::launch(config).await?;

    debug!("chromedriver started");

    tokio::spawn(async move {
        while let Some(res) = handler.next().await {
            res.unwrap();
        }
    });

    let page = browser
        .new_page(&format!("http://{}:{}/index.html", wasm_ip, wasm_port))
        .await?;

    tokio::spawn(register_listeners(&page).await?);

    page.wait_for_navigation().await?;
    // Note that `format!` needs double {{ }} in order to escape them.
    let _ = page
        .evaluate_function(&format!(
            r#"
                async function() {{
                    await window.worker.init();
                    // Do not `await` run() or else it will block the browser. 
                    window.worker.run("{}", {}, {}, {}, {});
                }}
            "#,
            ws_ip.to_string(),
            ws_port,
            wasm_to_server_port,
            wasm_to_verifier_port,
            wasm_to_native_port
        ))
        .await?;

    Ok(browser)
}

pub fn spawn_http_server(ip: IpAddr, port: u16) -> anyhow::Result<JoinHandle<()>> {
    let handle = tokio::spawn(async move {
        // Serve embedded files with additional headers.
        let data_serve = warp_embed::embed(&Data);

        let data_serve_with_headers = data_serve
            .map(|reply| {
                warp::reply::with_header(reply, "Cross-Origin-Opener-Policy", "same-origin")
            })
            .map(|reply| {
                warp::reply::with_header(reply, "Cross-Origin-Embedder-Policy", "require-corp")
            });

        warp::serve(data_serve_with_headers).run((ip, port)).await;
    });

    Ok(handle)
}

async fn register_listeners(page: &Page) -> Result<impl Future<Output = ()>> {
    let mut logs = page.event_listener::<EventEntryAdded>().await?.fuse();
    let mut exceptions = page.event_listener::<EventExceptionThrown>().await?.fuse();

    Ok(futures::future::join(
        async move {
            while let Some(event) = logs.next().await {
                let entry = &event.entry;
                match entry.level {
                    LogEntryLevel::Error => {
                        error!("{:?}", entry);
                    }
                    _ => {
                        debug!("{:?}: {}", entry.timestamp, entry.text);
                    }
                }
            }
        },
        async move {
            while let Some(event) = exceptions.next().await {
                error!("{:?}", event);
            }
        },
    )
    .map(|_| ()))
}
