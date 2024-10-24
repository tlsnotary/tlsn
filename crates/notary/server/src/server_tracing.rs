use eyre::Result;
use std::str::FromStr;
use tracing::Level;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Registry};

use crate::config::NotaryServerProperties;

pub fn init_tracing(config: &NotaryServerProperties) -> Result<()> {
    // Retrieve log filtering logic from config
    let directives = match &config.logging.filter {
        // Use custom filter that is provided by user
        Some(filter) => filter.clone(),
        // Use the default filter when only verbosity level is provided
        None => {
            let level = Level::from_str(&config.logging.level)?;
            format!("notary_server={level},tlsn_verifier={level},tls_mpc={level}")
        }
    };
    let filter_layer = EnvFilter::builder().parse(directives)?;

    // Format the log
    let format_layer = tracing_subscriber::fmt::layer()
        // Use a more compact, abbreviated log format
        .compact()
        .with_thread_ids(true)
        .with_thread_names(true);

    Registry::default()
        .with(filter_layer)
        .with(format_layer)
        .try_init()?;

    Ok(())
}
