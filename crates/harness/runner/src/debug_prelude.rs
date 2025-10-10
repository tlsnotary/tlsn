#![allow(unused_imports)]
pub use futures::FutureExt;

pub use tracing::{debug, error};

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
