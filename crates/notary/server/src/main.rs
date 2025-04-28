use eyre::{eyre, Result};
use notary_server::{init_tracing, run_server, CliFields, NotaryServerError, NotaryServerProperties};
use structopt::StructOpt;
use tracing::debug;

#[tokio::main]
async fn main() -> Result<(), NotaryServerError> {
    // Load command line arguments
    let cli_fields: CliFields = CliFields::from_args();

    let config =
        NotaryServerProperties::new(&cli_fields).map_err(|err| eyre!("Failed to load config: {}", err))?;

    // Set up tracing for logging
    init_tracing(&config).map_err(|err| eyre!("Failed to set up tracing: {err}"))?;

    debug!("Server config loaded: \n{}", config);

    // Run the server
    run_server(&config).await?;

    Ok(())
}
