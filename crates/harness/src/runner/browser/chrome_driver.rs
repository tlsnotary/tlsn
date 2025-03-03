use anyhow::{anyhow, Result};
use chromiumoxide::{
    cdp::{
        browser_protocol::{
            log::{EventEntryAdded, LogEntryLevel},
            page::ReloadParams,
        },
        js_protocol::runtime::EventExceptionThrown,
    },
    Browser, BrowserConfig, Page,
};
use futures::{Future, FutureExt, StreamExt};
use std::{env, time::Duration};
use tracing::{debug, error, instrument};

use crate::{DEFAULT_SERVER_IP, DEFAULT_WASM_PORT};

#[instrument]
pub async fn start_browser() -> Result<(Browser, Page)> {
    let config = BrowserConfig::builder()
        .request_timeout(Duration::from_secs(60))
        //.with_head()
        .disable_cache()
        //.incognito() // Run in incognito mode to avoid unexplained WS connection errors in chromiumoxide.
        .build()
        .map_err(|s| anyhow!(s))?;

    debug!("launching chromedriver");

    let (browser, mut handler) = Browser::launch(config).await?;

    debug!("chromedriver started");

    tokio::spawn(async move {
        while let Some(res) = handler.next().await {
            if let Err(e) = res {
                error!("error: {:?}", e);
            }
        }
    });

    let wasm_port: u16 = env::var("WASM_PORT")
        .map(|port| port.parse().expect("port should be valid integer"))
        .unwrap_or(DEFAULT_WASM_PORT);
    let wasm_addr: String = env::var("WASM_IP").unwrap_or_else(|_| DEFAULT_SERVER_IP.to_string());

    let page = browser
        .new_page(&format!("http://{}:{}/index.html", wasm_addr, wasm_port))
        .await?;

    tokio::spawn(register_listeners(&page).await?);

    page.execute(ReloadParams::builder().ignore_cache(true).build())
        .await?;
    page.wait_for_navigation().await?;

    Ok((browser, page))
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
