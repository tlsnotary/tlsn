use crate::{CliFields, NotaryServerProperties};
use config::{Config, ConfigError, Environment, File};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct Settings {
    #[serde(flatten)]
    pub config: NotaryServerProperties,
}

impl Settings {
    pub fn new(cli_fields: &CliFields) -> Result<Self, ConfigError> {
        let config_path = Path::new(&cli_fields.config_file);

        let mut builder = Config::builder()
            // Load base configuration
            .add_source(File::from(config_path))
            // Add in settings from environment variables (with a prefix of NOTARY_SERVER and '__'
            // as separator).
            .add_source(
                Environment::with_prefix("NOTARY_SERVER")
                    .try_parsing(true)
                    .prefix_separator("__")
                    .separator("__"),
            );

        // Apply CLI argument overrides
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

        let settings: Settings = config.try_deserialize()?;

        Ok(settings)
    }
}
