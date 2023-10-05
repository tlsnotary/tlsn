use eyre::Result;
use opentelemetry::{
    global,
    sdk::{export::trace::stdout, propagation::TraceContextPropagator},
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Registry};

use crate::config::NotaryServerProperties;

pub fn init_tracing(config: &NotaryServerProperties) -> Result<()> {
    // Create a new OpenTelemetry pipeline
    let tracer = stdout::new_pipeline().install_simple();

    // Create a tracing layer with the configured tracer
    let tracing_layer = tracing_opentelemetry::layer().with_tracer(tracer);

    // Set the log level
    let env_filter_layer = EnvFilter::new(&config.tracing.default_level);

    // Format the log
    let format_layer = tracing_subscriber::fmt::layer()
        // Use a more compact, abbreviated log format
        .compact()
        .with_thread_ids(true)
        .with_thread_names(true);

    // Set up context propagation
    global::set_text_map_propagator(TraceContextPropagator::default());

    Registry::default()
        .with(tracing_layer)
        .with(env_filter_layer)
        .with(format_layer)
        .try_init()?;

    Ok(())
}
