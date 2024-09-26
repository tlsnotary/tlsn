use config::{Config, ConfigError, Environment, File};
use std::path::Path;
use tracing::{info, warn, debug};
use crate::{CliFields, NotaryServerProperties};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Settings {
    #[serde(flatten)]
    pub config: NotaryServerProperties,
}

impl Settings {
    pub fn new(cli_fields: &CliFields) -> Result<Self, ConfigError> {
        let mut builder = Config::builder();

        // Add the config file if it exists
        let config_path = Path::new(&cli_fields.config_file);

        if config_path.exists() {
            info!("Loading configuration from: {}", cli_fields.config_file);
            builder = builder.add_source(File::from(config_path));
        } else {
            warn!("Config file not found: {}. Using defaults and overrides.", cli_fields.config_file);
        }

        // Add environment variables
        builder = builder.add_source(Environment::with_prefix("NOTARY_SERVER").separator("__"));

        // Add CLI overrides
        if let Some(port) = cli_fields.port {
            builder = builder.set_override("server.port", port)?;
        }
        if let Some(tls_enabled) = cli_fields.tls_enabled {
            builder = builder.set_override("tls.enabled", tls_enabled)?;
        }
        if let Some(log_level) = &cli_fields.log_level {
            builder = builder.set_override("logging.level", log_level.clone())?;
        }

        let config = builder.build()?;

        // Log the entire configuration for debugging
        debug!("Loaded configuration: {:#?}", config);

        let settings: Settings = config.try_deserialize()?;

        Ok(settings)
    }
}