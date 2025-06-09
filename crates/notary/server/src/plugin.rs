use std::{path::Path, time::Duration};

use extism::{convert::Json, *};
use eyre::{eyre, Result};
use serde::{Deserialize, Serialize};
use tlsn_common::config::ProtocolConfigValidator;
use tlsn_core::{VerifierOutput, VerifyConfig};
use tlsn_verifier::{Verifier, VerifierConfig};
use tokio::{io::{AsyncRead, AsyncWrite}, time::timeout};
use tokio_util::compat::TokioAsyncReadCompatExt;
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
        // .with_function("verify", [PTR], [PTR], UserData::new(notary_globals.clone()), verify)
        .build()
        .map_err(|e| eyre!("Failed to build plugin: {}", e))?;

    debug!("Plugin built successfully");

    let plugin_config = plugin.call::<(), PluginVerifierConfig>("config", ())
        .map_err(|e| eyre!("Failed to get plugin config: {}", e))?;
    
    let max_sent_data = plugin_config.max_sent_data.unwrap_or(notary_globals.notarization_config.max_sent_data);
    let max_recv_data = plugin_config.max_recv_data.unwrap_or(notary_globals.notarization_config.max_recv_data);
    
    let mut validator_builder = ProtocolConfigValidator::builder();
    validator_builder
        .max_sent_data(max_sent_data)
        .max_recv_data(max_recv_data);

    if let Some(max_sent_records) = plugin_config.max_sent_records {
        validator_builder.max_sent_records(max_sent_records);
    }
    if let Some(max_recv_records) = plugin_config.max_recv_records {
        validator_builder.max_recv_records_online(max_recv_records);
    }
    let validator = validator_builder.build()?;

    let config = VerifierConfig::builder()
        .protocol_config_validator(validator)
        .crypto_provider(notary_globals.crypto_provider.clone())
        .build()?;

    let output = timeout(
        Duration::from_secs(notary_globals.notarization_config.timeout),
        Verifier::new(config).verify(socket.compat(), &VerifyConfig::default()),
    )
    .await
    .map_err(|_| eyre!("Timeout reached before verification completes"))??;

    plugin.call::<Json<VerifierOutput>, ()>("verify", Json(output))
        .map_err(|e| eyre!("Failed to call verify on plugin: {}", e))?;

    Ok(())
}

// !!! Experiment with plugin controlled `verify` host function
// host_fn!(verify(notary_globals: NotaryGlobals; verifier_config: PluginVerifierConfig) -> Json<VerifierOutput> {
//     let notary_globals = notary_globals.get()?;
//     let notary_globals = notary_globals.lock().unwrap();

//     let max_sent_data = verifier_config.max_sent_data.unwrap_or(notary_globals.notarization_config.max_sent_data);
//     let max_recv_data = verifier_config.max_recv_data.unwrap_or(notary_globals.notarization_config.max_recv_data);
    
//     let mut validator_builder = ProtocolConfigValidator::builder();
//     validator_builder
//         .max_sent_data(max_sent_data)
//         .max_recv_data(max_recv_data);

//     if let Some(max_sent_records) = verifier_config.max_sent_records {
//         validator_builder.max_sent_records(max_sent_records);
//     }
//     if let Some(max_recv_records) = verifier_config.max_recv_records {
//         validator_builder.max_recv_records(max_recv_records);
//     }
//     let validator = validator_builder.build()?;

//     let config = VerifierConfig::builder()
//             .protocol_config_validator(validator)
//             .crypto_provider(notary_globals.crypto_provider.clone())
//             .build()?;

//     debug!("Verifier configuration: {:?}", config);

//     // Doesn't work to have nested runtime?

//     // let output = rt.block_on(async {
//         // let output = Verifier::new(config).verify(socket.compat(), &VerifyConfig::default())
//         //     .await
//         //     .unwrap();
//     //     output
//     // });

//     Ok(Json(VerifierOutput {
//         server_name: Default::default(),
//         transcript: Default::default(),
//         transcript_commitments: Default::default(),
//     }))
// });
