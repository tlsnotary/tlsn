use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct NotaryServerProperties {
    /// Name and address of the notary server
    pub server: ServerProperties,
    /// Setting for notarization
    pub notarization: NotarizationProperties,
    /// File path of private key and certificate (in PEM format) used for establishing TLS with prover
    pub tls_signature: TLSSignatureProperties,
    /// File path of private key (in PEM format) used to sign the notarization
    pub notary_signature: NotarySignatureProperties,
    /// Setting for logging/tracing
    pub tracing: TracingProperties,
    /// Setting for authorization
    pub authorization: AuthorizationProperties,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AuthorizationProperties {
    /// Switch to turn on or off auth middleware
    pub enabled: bool,
    /// File path of the whitelist API key csv
    pub whitelist_csv_path: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct NotarizationProperties {
    /// Global limit for maximum transcript size in bytes
    pub max_transcript_size: usize,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ServerProperties {
    /// Used for testing purpose
    pub name: String,
    pub host: String,
    pub port: u16,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TLSSignatureProperties {
    pub private_key_pem_path: String,
    pub certificate_pem_path: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct NotarySignatureProperties {
    pub private_key_pem_path: String,
    pub public_key_pem_path: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TracingProperties {
    /// The minimum logging level, must be either of <https://docs.rs/tracing/latest/tracing/struct.Level.html#implementations>
    pub default_level: String,
}
