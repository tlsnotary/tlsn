use structopt::StructOpt;

/// Fields loaded from the command line when launching this server.
#[derive(Clone, Debug, StructOpt)]
#[structopt(name = "Notary Server")]
pub struct CliFields {
    /// Configuration file location
    #[structopt(long, default_value = "./config/config.yaml")]
    pub config_file: String,

    /// Port of notary server
    #[structopt(long)]
    pub port: Option<u16>,

    /// Flag to turn on/off TLS when connecting to prover
    #[structopt(long)]
    pub tls_enabled: Option<bool>,

    /// Level of logging
    #[structopt(long)]
    pub log_level: Option<String>,
}
