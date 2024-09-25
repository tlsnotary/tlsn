use config::{Config, ConfigError, Environment, File};
use std::path::Path;
use tracing::{info, warn};
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

        // Add default values
        builder = builder
            .set_default("server.name", "notary-server")?
            .set_default("server.host", "0.0.0.0")?
            .set_default("server.port", 7047)?
            .set_default("server.html-info", "<h1>Notary Server</h1>")?
            .set_default("notarization.max-sent-data", 4096)?
            .set_default("notarization.max-recv-data", 16384)?
            .set_default("tls.enabled", true)?
            .set_default("tls.private-key-pem-path", "../fixture/tls/notary.key")?
            .set_default("tls.certificate-pem-path", "../fixture/tls/notary.crt")?
            .set_default("notary-key.private-key-pem-path", "../fixture/notary/notary.key")?
            .set_default("notary-key.public-key-pem-path", "../fixture/notary/notary.pub")?
            .set_default("logging.level", "DEBUG")?
            .set_default("logging.filter", Option::<String>::None)?
            .set_default("authorization.enabled", false)?
            .set_default("authorization.whitelist-csv-path", "../fixture/auth/whitelist.csv")?;

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
        let settings: Settings = config.try_deserialize()?;

        // Validate file existence
        Self::validate_file_exists(&settings.config.tls.private_key_pem_path, "TLS private key")?;
        Self::validate_file_exists(&settings.config.tls.certificate_pem_path, "TLS certificate")?;
        Self::validate_file_exists(&settings.config.notary_key.private_key_pem_path, "Notary private key")?;
        Self::validate_file_exists(&settings.config.notary_key.public_key_pem_path, "Notary public key")?;

        Ok(settings)
    }

    fn validate_file_exists(path: &str, file_type: &str) -> Result<(), ConfigError> {
        if !Path::new(path).exists() {
            Err(ConfigError::NotFound(format!("{} file not found: {}", file_type, path)))
        } else {
            Ok(())
        }
    }
}