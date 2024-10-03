use anyhow::{anyhow, Result};
use chromiumoxide::{
    cdp::{
        browser_protocol::log::{EventEntryAdded, LogEntryLevel},
        js_protocol::runtime::EventExceptionThrown,
    },
    Browser, BrowserConfig, Page,
};
use futures::{Future, FutureExt, StreamExt};
use std::{env, time::Duration};
use tracing::{debug, error, instrument};

use crate::{TestResult, DEFAULT_SERVER_IP, DEFAULT_WASM_PORT};

#[instrument]
pub async fn run() -> Result<Vec<TestResult>> {
    let config = BrowserConfig::builder()
        .request_timeout(Duration::from_secs(60))
        .incognito() // Run in incognito mode to avoid unexplained WS connection errors in chromiumoxide.
        .build()
        .map_err(|s| anyhow!(s))?;

    debug!("launching chromedriver");

    let (mut browser, mut handler) = Browser::launch(config).await?;

    debug!("chromedriver started");

    tokio::spawn(async move {
        while let Some(res) = handler.next().await {
            res.unwrap();
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

    page.wait_for_navigation().await?;
    let results: Vec<TestResult> = page
        .evaluate(
            r#"
                (async () => {
                    await window.testWorker.init();
                    return await window.testWorker.run();
                })();
            "#,
        )
        .await?
        .into_value()?;

    browser.close().await?;
    browser.wait().await?;

    Ok(results)
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
