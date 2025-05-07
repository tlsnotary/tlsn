use config::{Config, Environment};
use eyre::{eyre, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::{parse_config_file, util::prepend_file_path, CliFields};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NotaryServerProperties {
    pub host: String,
    pub port: u16,
    /// Static html response returned from API root endpoint "/". Default html
    /// response contains placeholder strings that will be replaced with
    /// actual values in server.rs, e.g. {version}, {public_key}
    pub html_info: String,
    /// The maximum number of concurrent notarization sessions
    pub concurrency: usize,
    /// Setting for notarization
    pub notarization: NotarizationProperties,
    /// Setting for TLS connection between prover and notary
    pub tls: TLSProperties,
    /// Setting for logging
    pub log: LogProperties,
    /// Setting for authorization
    pub auth: AuthorizationProperties,
}

impl NotaryServerProperties {
    pub fn new(cli_fields: &CliFields) -> Result<Self> {
        // Uses config file if given.
        if let Some(config_path) = &cli_fields.config {
            let mut config: NotaryServerProperties = parse_config_file(config_path)?;

            // Ensures all relative file paths in the config file are prepended with
            // the config file's parent directory, so that server binary can be run from
            // anywhere.
            let parent_dir = Path::new(config_path)
                .parent()
                .ok_or(eyre!("Failed to get parent directory of config file"))?
                .to_str()
                .ok_or_else(|| eyre!("Failed to convert path to str"))?
                .to_string();

            // Prepend notarization key path.
            if let Some(path) = &config.notarization.private_key_path {
                config.notarization.private_key_path = Some(prepend_file_path(path, &parent_dir)?);
            }
            // Prepend TLS key paths.
            if let Some(path) = &config.tls.private_key_path {
                config.tls.private_key_path = Some(prepend_file_path(path, &parent_dir)?);
            }
            if let Some(path) = &config.tls.certificate_path {
                config.tls.certificate_path = Some(prepend_file_path(path, &parent_dir)?);
            }
            // Prepend auth whitelist path.
            if let Some(path) = &config.auth.whitelist_path {
                config.auth.whitelist_path = Some(prepend_file_path(path, &parent_dir)?);
            }

            Ok(config)
        } else {
            let default_config = Config::try_from(&NotaryServerProperties::default())?;

            let config = Config::builder()
                .add_source(default_config)
                // Add in settings from environment variables (with a prefix of NS and '_' as
                // separator).
                .add_source(
                    Environment::with_prefix("NS")
                        .try_parsing(true)
                        .prefix_separator("_")
                        .separator("__"),
                )
                .build()?
                .try_deserialize()?;

            Ok(config)
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NotarizationProperties {
    /// Global limit for maximum number of bytes that can be sent
    pub max_sent_data: usize,
    /// Global limit for maximum number of bytes that can be received
    pub max_recv_data: usize,
    /// Number of seconds before notarization timeouts to prevent unreleased
    /// memory
    pub timeout: u64,
    /// File path of private key (in PEM format) used to sign the notarization
    pub private_key_path: Option<String>,
    /// Signature algorithm used to generate a random private key when
    /// private_key_path is not set
    pub signature_algorithm: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct TLSProperties {
    /// Flag to turn on/off TLS between prover and notary — should always be
    /// turned on unless either
    /// (1) TLS is handled by external setup e.g. reverse proxy cloud; or
    /// (2) For local testing
    pub enabled: bool,
    /// File path of TLS private key (in PEM format)
    pub private_key_path: Option<String>,
    /// File path of TLS cert (in PEM format)
    pub certificate_path: Option<String>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum LogFormat {
    Compact,
    Json,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogProperties {
    /// Log verbosity level of the default filtering logic, which is
    /// notary_server=<level>,tlsn_verifier=<level>,mpc_tls=<level>
    /// Must be either of <https://docs.rs/tracing/latest/tracing/struct.Level.html#implementations>
    pub level: String,
    /// Custom filtering logic, refer to the syntax here https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html#example-syntax
    /// This will override the default filtering logic above
    pub filter: Option<String>,
    /// Log format. Available options are "COMPACT" and "JSON"
    pub format: LogFormat,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct AuthorizationProperties {
    /// Flag to turn on or off auth middleware
    pub enabled: bool,
    /// File path of the API key whitelist (in CSV format)
    pub whitelist_path: Option<String>,
}

impl Default for NotaryServerProperties {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 7047,
            html_info: r#"
                <head>
                    <meta charset='UTF-8'>
                    <meta name='author' content='tlsnotary'>
                    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
                </head>
                <body>
                    <svg width='86' height='88' viewBox='0 0 86 88' fill='none' xmlns='http://www.w3.org/2000/svg'>
                    <path d='M25.5484 0.708986C25.5484 0.17436 26.1196 -0.167376 26.5923 0.0844205L33.6891 3.86446C33.9202 3.98756 34.0645 4.22766 34.0645 4.48902V9.44049H37.6129C38.0048 9.44049 38.3226 9.75747 38.3226 10.1485V21.4766L36.1936 20.0606V11.5645H34.0645V80.9919C34.0645 81.1134 34.0332 81.2328 33.9735 81.3388L30.4251 87.6388C30.1539 88.1204 29.459 88.1204 29.1878 87.6388L25.6394 81.3388C25.5797 81.2328 25.5484 81.1134 25.5484 80.9919V0.708986Z' fill='#243F5F'/>
                    <path d='M21.2903 25.7246V76.7012H12.7742V34.2207H0V25.7246H21.2903Z' fill='#243F5F'/>
                    <path d='M63.871 76.7012H72.3871V34.2207H76.6452V76.7012H85.1613V25.7246H63.871V76.7012Z' fill='#243F5F'/>
                    <path d='M38.3226 25.7246H59.6129V34.2207H46.8387V46.9649H59.6129V76.7012H38.3226V68.2051H51.0968V55.4609H38.3226V25.7246Z' fill='#243F5F'/>
                    </svg>
                    <h1>Notary Server {version}!</h1>
                    <ul>
                    <li>public key: <pre>{public_key}</pre></li>
                    <li>git commit hash: <a href='https://github.com/tlsnotary/tlsn/commit/{git_commit_hash}'>{git_commit_hash}</a></li>
                    <li><a href='healthcheck'>health check</a></li>
                    <li><a href='info'>info</a></li>
                    </ul>
                </body>
            "#.to_string(),
            concurrency: 32,
            notarization: Default::default(),
            tls: Default::default(),
            log: Default::default(),
            auth: Default::default(),
        }
    }
}

impl Default for NotarizationProperties {
    fn default() -> Self {
        Self {
            max_sent_data: 4096,
            max_recv_data: 16384,
            timeout: 1800,
            private_key_path: None,
            signature_algorithm: "secp256k1".to_string(),
        }
    }
}

impl Default for LogProperties {
    fn default() -> Self {
        Self {
            level: "DEBUG".to_string(),
            filter: None,
            format: LogFormat::Compact,
        }
    }
}

impl std::fmt::Display for NotaryServerProperties {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "host: {}", self.host)?;
        writeln!(f, "port: {}", self.port)?;
        writeln!(f, "html_info: {}", self.html_info)?;
        writeln!(f, "concurrency: {}", self.concurrency)?;
        writeln!(f, "notarization: \n{}", self.notarization)?;
        writeln!(f, "tls: \n{}", self.tls)?;
        writeln!(f, "log: \n{}", self.log)?;
        write!(f, "auth: \n{}", self.auth)
    }
}

impl std::fmt::Display for NotarizationProperties {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "   max_sent_data: {}", self.max_sent_data)?;
        writeln!(f, "   max_recv_data: {}", self.max_recv_data)?;
        writeln!(f, "   timeout: {}", self.timeout)?;
        writeln!(f, "   private_key_path: {:?}", self.private_key_path)?;
        write!(f, "   signature_algorithm: {}", self.signature_algorithm)
    }
}

impl std::fmt::Display for TLSProperties {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "   enabled: {}", self.enabled)?;
        writeln!(f, "   private_key_path: {:?}", self.private_key_path)?;
        write!(f, "   certificate_path: {:?}", self.certificate_path)
    }
}

impl std::fmt::Display for LogProperties {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "   level: {}", self.level)?;
        writeln!(f, "   filter: {:?}", self.filter)?;
        write!(f, "   format: {:?}", self.format)
    }
}

impl std::fmt::Display for AuthorizationProperties {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "   enabled: {}", self.enabled)?;
        write!(f, "   whitelist_path: {:?}", self.whitelist_path)
    }
}
