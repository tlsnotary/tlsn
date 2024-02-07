use eyre::Result;
use tracing::metadata::LevelFilter;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Registry};

use crate::config::NotaryServerProperties;

pub fn init_tracing(config: &NotaryServerProperties) -> Result<()> {
    // Retrieve log filter logic from config
    let env_filter_layer = EnvFilter::builder()
        // if fail to parse log filter, then set DEBUG level logging for all crates
        .with_default_directive(LevelFilter::DEBUG.into())
        .parse_lossy(&config.tracing.logging_filter);

    // Format the log
    let format_layer = tracing_subscriber::fmt::layer()
        // Use a more compact, abbreviated log format
        .compact()
        .with_thread_ids(true)
        .with_thread_names(true);

    Registry::default()
        .with(env_filter_layer)
        .with(format_layer)
        .try_init()?;

    Ok(())
}
