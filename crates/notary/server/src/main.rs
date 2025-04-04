use eyre::{eyre, Result};
use notary_server::{init_tracing, run_server, CliFields, NotaryServerError, Settings};
use structopt::StructOpt;
use tracing::debug;

#[tokio::main]
async fn main() -> Result<(), NotaryServerError> {
    std::env::set_current_dir(env!("CARGO_MANIFEST_DIR"))
        .map_err(|err| eyre!("Failed to set CWD: {err}"))?;

    // Load command line arguments
    let cli_fields: CliFields = CliFields::from_args();

    let settings =
        Settings::new(&cli_fields).map_err(|err| eyre!("Failed to load settings: {err}"))?;

    // Set up tracing for logging
    init_tracing(&settings.config).map_err(|err| eyre!("Failed to set up tracing: {err}"))?;

    debug!(?settings.config, "Server config loaded");

    // Run the server
    run_server(&settings.config).await?;

    Ok(())
}
