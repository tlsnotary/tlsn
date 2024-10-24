use structopt::StructOpt;

/// Fields loaded from the command line when launching this server.
#[derive(Clone, Debug, StructOpt)]
#[structopt(name = "Notary Server")]
pub struct CliFields {
    /// Configuration file location
    #[structopt(long, default_value = "./config/config.yaml")]
    pub config_file: String,
}
