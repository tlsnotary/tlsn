use std::{path::Path, time::Duration};

use extism::{convert::Json, *};
use eyre::{eyre, Result};
use serde::{Deserialize, Serialize};
use tlsn_common::config::ProtocolConfigValidator;
use tlsn_core::{
    connection::ServerName,
    transcript::{
        encoding::EncodingCommitment, hash::PlaintextHash, Idx, PartialTranscript as CorePartialTranscript, TranscriptCommitment as CoreTranscriptCommitment
    },
    VerifierOutput as CoreVerifierOutput, VerifyConfig
};
use tlsn_verifier::{Verifier, VerifierConfig};
use tokio::{io::{AsyncRead, AsyncWrite}, time::timeout};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::debug;

use crate::{types::NotaryGlobals, NotaryServerError};

#[derive(Deserialize, FromBytes, Serialize, ToBytes, Debug)]
#[encoding(Json)]
#[serde(rename_all = "camelCase")]
struct PluginVerifierConfig {
    /// Maximum number of bytes that can be sent.
    max_sent_data: Option<usize>,
    /// Maximum number of application data records that can be sent.
    max_sent_records: Option<usize>,
    /// Maximum number of bytes that can be received.
    max_recv_data: Option<usize>,
    /// Maximum number of application data records that can be received.
    max_recv_records_online: Option<usize>,
}

#[derive(Deserialize, FromBytes, Serialize, ToBytes)]
#[encoding(Json)]
#[serde(rename_all = "camelCase")]
struct VerifierOutput {
    /// Server identity.
    pub server_name: Option<ServerName>,
    /// Transcript data.
    pub transcript: Option<PartialTranscript>,
    /// Transcript commitments.
    pub transcript_commitments: Vec<TranscriptCommitment>,
}

impl From<CoreVerifierOutput> for VerifierOutput {
    fn from(output: CoreVerifierOutput) -> Self {
        Self {
            server_name: output.server_name,
            transcript: output.transcript.map(PartialTranscript::from),
            transcript_commitments: output.transcript_commitments.into_iter()
                .map(TranscriptCommitment::from)
                .collect(),
        }
    }
}

#[derive(Deserialize, FromBytes, Serialize, ToBytes)]
#[encoding(Json)]
#[serde(rename_all = "camelCase")]
struct PartialTranscript {
    /// Data sent from the Prover to the Server.
    sent: Vec<u8>,
    /// Data received by the Prover from the Server.
    received: Vec<u8>,
    /// Index of `sent` which have been authenticated.
    sent_authed_idx: Idx,
    /// Index of `received` which have been authenticated.
    recv_authed_idx: Idx,
}

impl From<CorePartialTranscript> for PartialTranscript {
    fn from(transcript: CorePartialTranscript) -> Self {
        Self {
            sent: transcript.sent_unsafe().to_vec(),
            received: transcript.received_unsafe().to_vec(),
            sent_authed_idx: transcript.sent_authed().clone(),
            recv_authed_idx: transcript.received_authed().clone(),
        }
    }
}

#[derive(Deserialize, FromBytes, Serialize, ToBytes)]
#[encoding(Json)]
#[non_exhaustive]
enum TranscriptCommitment {
    /// Encoding commitment.
    #[serde(rename = "encodingCommitment")]
    Encoding(EncodingCommitment),
    /// Plaintext hash commitment.
    #[serde(rename = "plaintextHash")]
    Hash(PlaintextHash),
}

impl From<CoreTranscriptCommitment> for TranscriptCommitment {
    fn from(commitment: tlsn_core::transcript::TranscriptCommitment) -> Self {
        match commitment {
            tlsn_core::transcript::TranscriptCommitment::Encoding(encoding) => {
                TranscriptCommitment::Encoding(encoding)
            },
            tlsn_core::transcript::TranscriptCommitment::Hash(hash) => {
                TranscriptCommitment::Hash(hash)
            },
            _ => panic!("Unsupported transcript commitment type in plugin output"),
        }
    }
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

    debug!("Plugin configuration: {:?}", plugin_config);
    
    let max_sent_data = plugin_config.max_sent_data.unwrap_or(notary_globals.notarization_config.max_sent_data);
    let max_recv_data = plugin_config.max_recv_data.unwrap_or(notary_globals.notarization_config.max_recv_data);
    
    let mut validator_builder = ProtocolConfigValidator::builder();
    validator_builder
        .max_sent_data(max_sent_data)
        .max_recv_data(max_recv_data);

    if let Some(max_sent_records) = plugin_config.max_sent_records {
        validator_builder.max_sent_records(max_sent_records);
    }
    if let Some(max_recv_records_online) = plugin_config.max_recv_records_online {
        validator_builder.max_recv_records_online(max_recv_records_online);
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

    plugin.call::<VerifierOutput, ()>("verify", output.into())
        .map_err(|e| eyre!("Failed to verify on plugin: {}", e))?;

    plugin.reset()
        .map_err(|e| eyre!("Failed to reset plugin memory: {}", e))?;

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
