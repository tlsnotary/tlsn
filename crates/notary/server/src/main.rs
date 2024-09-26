use eyre::{eyre, Result};
use structopt::StructOpt;
use tracing::{info, debug, error};
use notary_server::{
    init_tracing, run_server, CliFields, NotaryServerError,
    Settings
};

#[tokio::main]
async fn main() -> Result<(), NotaryServerError> {
    // Load command line arguments
    let cli_fields: CliFields = CliFields::from_args();

    let settings = match Settings::new(&cli_fields) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to load settings: {:?}. Check that all required fields are provided in the configuration.", e);
            return Err(eyre!(
            "Failed to load settings: {:?}. Ensure required fields (like `server.port`, `tls.enabled`, etc.) are present.",
            e
        ).into());
        }
    };

    // Print the entire configuration for debugging
    println!("Loaded settings: {:#?}", settings);

    // Set up tracing for logging
    init_tracing(&settings.config)
        .map_err(|err| eyre!("Failed to set up tracing: {err}"))?;

    debug!(?settings, "Server settings loaded");
    info!("Server port: {}", settings.config.server.port);
    info!("TLS enabled: {}", settings.config.tls.enabled);
    info!("Log level: {}", settings.config.logging.level);

    // Run the server
    run_server(&settings.config).await?;

    Ok(())
}