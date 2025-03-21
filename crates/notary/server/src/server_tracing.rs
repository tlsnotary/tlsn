use eyre::Result;
use std::str::FromStr;
use tracing::{Level, Subscriber};
use tracing_subscriber::{
    fmt, layer::SubscriberExt, registry::LookupSpan, util::SubscriberInitExt, EnvFilter, Layer,
    Registry,
};

use crate::config::{LogFormat, NotaryServerProperties};

fn format_layer<S>(format: LogFormat) -> Box<dyn Layer<S> + Send + Sync>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    let f = fmt::layer().with_thread_ids(true).with_thread_names(true);
    match format {
        LogFormat::Compact => f.compact().boxed(),
        LogFormat::Json => f.json().boxed(),
    }
}

pub fn init_tracing(config: &NotaryServerProperties) -> Result<()> {
    // Retrieve log filtering logic from config
    let directives = match &config.logging.filter {
        // Use custom filter that is provided by user
        Some(filter) => filter.clone(),
        // Use the default filter when only verbosity level is provided
        None => {
            let level = Level::from_str(&config.logging.level)?;
            format!("notary_server={level},tlsn_verifier={level},mpc_tls={level}")
        }
    };
    let filter_layer = EnvFilter::builder().parse(directives)?;

    Registry::default()
        .with(filter_layer)
        .with(format_layer(config.logging.format))
        .try_init()?;

    Ok(())
}
