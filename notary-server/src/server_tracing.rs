use eyre::Result;
use tracing::metadata::LevelFilter;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Registry};

pub fn init_tracing() -> Result<()> {
    // Retrieve log filter logic from RUST_LOG env var
    let env_filter_layer = EnvFilter::builder()
        // if RUST_LOG is not set, then set DEBUG level logging for all crates
        .with_default_directive(LevelFilter::DEBUG.into())
        .from_env_lossy();

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
