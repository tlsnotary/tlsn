#![allow(unused_imports)]
#[cfg(feature = "debug")]
pub use futures::FutureExt;

#[cfg(feature = "debug")]
pub use tracing::{debug, error};

#[cfg(feature = "debug")]
pub use chromiumoxide::{
    Browser, Page,
    cdp::{
        browser_protocol::{
            log::{EventEntryAdded, LogEntryLevel},
            network::{EnableParams, SetCacheDisabledParams},
            page::ReloadParams,
        },
        js_protocol::runtime::EventExceptionThrown,
    },
    handler::HandlerConfig,
};
