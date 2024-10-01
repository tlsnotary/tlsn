use eyre::{eyre, Result};
use structopt::StructOpt;
use tracing::debug;
use notary_server::{
    init_tracing, run_server, CliFields, NotaryServerError,
    Settings
};

#[tokio::main]
async fn main() -> Result<(), NotaryServerError> {
    // Load command line arguments
    let cli_fields: CliFields = CliFields::from_args();

    let settings = Settings::new(&cli_fields)
        .map_err(|err| eyre!("Failed to load settings: {}", err))?;

    // Set up tracing for logging
    init_tracing(&settings.config)
        .map_err(|err| eyre!("Failed to set up tracing: {err}"))?;

    debug!(?settings.config, "Server config loaded");

    // Run the server
    run_server(&settings.config).await?;

    Ok(())
}