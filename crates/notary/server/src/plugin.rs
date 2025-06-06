use std::path::Path;

use extism::{convert::Json, *};
use eyre::{eyre, Result};
use serde::{Deserialize, Serialize};
use tlsn_common::config::ProtocolConfigValidator;
use tlsn_core::{CryptoProvider, VerifyConfig, VerifierOutput};
use tlsn_verifier::{Verifier, VerifierConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::debug;

use crate::{types::NotaryGlobals, NotaryServerError};

#[derive(Deserialize, FromBytes, Serialize, ToBytes, Debug)]
#[encoding(Json)]
struct PluginVerifierConfig {
    /// Maximum number of bytes that can be sent.
    max_sent_data: Option<usize>,
    /// Maximum number of application data records that can be sent.
    max_sent_records: Option<usize>,
    /// Maximum number of bytes that can be received.
    max_recv_data: Option<usize>,
    /// Maximum number of application data records that can be received.
    max_recv_records: Option<usize>,
}

host_fn!(verify(notary_globals: NotaryGlobals; verifier_config: PluginVerifierConfig) -> Json<VerifierOutput> {
    let notary_globals = notary_globals.get()?;
    let notary_globals = notary_globals.lock().unwrap();

    let max_sent_data = verifier_config.max_sent_data.unwrap_or(notary_globals.notarization_config.max_sent_data);
    let max_recv_data = verifier_config.max_recv_data.unwrap_or(notary_globals.notarization_config.max_recv_data);
    
    let mut validator_builder = ProtocolConfigValidator::builder();
    validator_builder
        .max_sent_data(max_sent_data)
        .max_recv_data(max_recv_data);

    if let Some(max_sent_records) = verifier_config.max_sent_records {
        validator_builder.max_sent_records(max_sent_records);
    }
    if let Some(max_recv_records) = verifier_config.max_recv_records {
        validator_builder.max_recv_records(max_recv_records);
    }
    let validator = validator_builder.build()?;

    let config = VerifierConfig::builder()
            .protocol_config_validator(validator)
            .crypto_provider(notary_globals.crypto_provider.clone())
            .build()?;

    debug!("Verifier configuration: {:?}", config);

    // Doesn't work to have nested runtime?
    // let rt = tokio::runtime::Runtime::new().unwrap();
    // let output = rt.block_on(async {
        // let output = Verifier::new(config).verify(socket.compat(), &VerifyConfig::default())
        //     .await
        //     .unwrap();
    //     output
    // });

    Ok(Json(VerifierOutput {
        server_name: Default::default(),
        transcript: Default::default(),
        transcript_commitments: Default::default(),
    }))
});

pub async fn verifier_service<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
    socket: T,
    notary_globals: NotaryGlobals,
    session_id: &str
) -> Result<(), NotaryServerError> {
    debug!(?session_id, "Starting verification...");

    let path = Wasm::file(Path::new(&notary_globals.plugin_config.path));
    let manifest = Manifest::new([path]);
    let mut plugin = PluginBuilder::new(manifest)
        .with_wasi(true)
        .with_function("verify", [PTR], [PTR], UserData::new(notary_globals.clone()), verify)
        .build()
        .map_err(|e| eyre!("Failed to build plugin: {}", e))?;

    debug!("Plugin built successfully");

    plugin.call::<(), ()>("plugin", ())
        .map_err(|e| eyre!("Failed to call plugin: {}", e))?;

    debug!("Plugin called successfully");

    Ok(())
}
