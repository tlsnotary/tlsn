use crate::{ CliFields, NotaryServerProperties };
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
            // Add in settings from environment variables (with a prefix of NOTARY_SERVER and '__' as separator).
            .add_source(
                Environment::with_prefix("NOTARY_SERVER")
                    .try_parsing(true)
                    .prefix_separator("__")
                    .separator("__")
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

#[cfg(test)]
mod test {
    use super::*;
    use std::env;
    use eyre::{eyre};
    use tracing::Level;
    use crate::config::NotaryServerProperties;

    #[test]
    fn test_settings_from_config_file(){
        let cli_fields: CliFields = CliFields {
            config_file: "./config/config.yaml".to_string(),
            port: None,
            tls_enabled: None,
            log_level: None
        };
        let settings: NotaryServerProperties =
            Settings::new(&cli_fields).map_err(|err| eyre!("Failed to load settings: {}", err)).unwrap().config;

        assert_eq!(settings.server.port,7047);
        assert_eq!(settings.tls.enabled, true);
    }

    #[test]
    fn test_settings_with_cli_override(){
        let cli_fields = CliFields {
            config_file: "./config/config.yaml".to_string(),
            port: Some(8080),
            tls_enabled: Some(false),
            log_level: Some(Level::INFO.to_string())
        };
        let settings: NotaryServerProperties =
            Settings::new(&cli_fields).map_err(|err| eyre!("Failed to load settings: {}", err)).unwrap().config;

        assert_eq!(settings.server.port,8080);
        assert_eq!(settings.tls.enabled, false);
    }

    #[test]
    fn test_settings_with_env_vars(){
        env::set_var("NOTARY_SERVER__SERVER__PORT", "3000");
        env::set_var("NOTARY_SERVER__NOTARIZATION__MAX_SENT_DATA", "3072");

        let cli_fields = CliFields {
            config_file: "./config/config.yaml".to_string(),
            port: None,
            tls_enabled: None,
            log_level: None
        };
        let settings: NotaryServerProperties =
            Settings::new(&cli_fields).map_err(|err| eyre!("Failed to load settings: {}", err)).unwrap().config;

        assert_eq!(settings.server.port, 3000);
        assert_eq!(settings.notarization.max_sent_data, 3072);

        env::remove_var("NOTARY_SERVER__SERVER__PORT");
        env::remove_var("NOTARY_SERVER__NOTARIZATION__MAX_SENT_DATA");
    }
}
