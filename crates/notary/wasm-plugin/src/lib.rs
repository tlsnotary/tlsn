use anyhow::{Error, anyhow};
use futures::{AsyncRead, AsyncWrite};
use notary_common::Input;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::from_str;
use std::{io, time::Duration};
use tlsn_common::config::ProtocolConfigValidator;
use tlsn_core::{CryptoProvider, VerifierOutput, VerifyConfig};
use tlsn_verifier::{Verifier, VerifierConfig};
use tracing::{debug, info};

const SERVER_DOMAIN: &str = "raw.githubusercontent.com";

#[derive(Deserialize, Serialize, Debug, Default)]
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

pub async fn run<S: AsyncRead + AsyncWrite + Send + Unpin + DeserializeOwned + 'static>() -> Result<(), Error> {
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();

    let output: String = input.chars().rev().collect();

    let input = from_str::<Input<S>>(&output)
        .map_err(|e| anyhow!("Failed to deserialize input: {}", e))?;

    let config = PluginVerifierConfig::default();
    debug!("Plugin configuration: {:?}", config);

    let max_sent_data = config
        .max_sent_data
        .unwrap_or(input.max_sent_data);
    let max_recv_data = config
        .max_recv_data
        .unwrap_or(input.max_recv_data);

    let mut validator_builder = ProtocolConfigValidator::builder();
    validator_builder
        .max_sent_data(max_sent_data)
        .max_recv_data(max_recv_data);

    if let Some(max_sent_records) = config.max_sent_records {
        validator_builder.max_sent_records(max_sent_records);
    }
    if let Some(max_recv_records_online) = config.max_recv_records_online {
        validator_builder.max_recv_records_online(max_recv_records_online);
    }
    let validator = validator_builder.build()?;

    let config = VerifierConfig::builder()
        .protocol_config_validator(validator)
        .crypto_provider(CryptoProvider::default())
        .build()?;

    debug!("Starting MPC-TLS...");

    let output = Verifier::new(config).verify(input.socket, &VerifyConfig::default())
        .await
        .map_err(|_| anyhow!("Timeout reached before verification completes"))?;

    debug!("Starting verification...");

    let VerifierOutput {
        server_name,
        transcript,
        transcript_commitments,
    } = output;

    debug!("Transcript commitments: {:?}", transcript_commitments);

    let transcript = transcript.ok_or(anyhow!("prover should have revealed transcript data"))?;
    let server_name = server_name.ok_or(anyhow!("prover should have revealed server name"))?;

    // Check sent data: check host.
    debug!("Starting sent data verification...");
    let sent: Vec<u8> = transcript
        .sent_unsafe()
        .into_iter()
        .map(|x| *x)
        .collect();
    let sent_data = String::from_utf8(sent.clone())
        .map_err(|err| anyhow!("Verifier expected sent data: {err}"))?;
    sent_data.find(SERVER_DOMAIN).ok_or(anyhow!(
        "Verification failed: Expected host {}",
        SERVER_DOMAIN
    ))?;

    // Check received data: check json and version number.
    debug!("Starting received data verification...");
    let received: Vec<u8> = transcript
        .received_unsafe()
        .into_iter()
        .map(|x| *x)
        .collect();
    let response = String::from_utf8(received.clone())
        .map_err(|err| anyhow!("Verifier expected received data: {err}"))?;

    response.find("123 Elm Street").ok_or(anyhow!(
        "Verification failed: missing data in received data"
    ))?;

    // Check Session info: server name.
    if server_name.as_str() != SERVER_DOMAIN {
        return Err(anyhow!("Verification failed: server name mismatches").into());
    }

    let sent_string = bytes_to_redacted_string(&sent)?;
    let received_string = bytes_to_redacted_string(&received)?;

    info!("Successfully verified {}", SERVER_DOMAIN);
    info!("Verified sent data:\n{}", sent_string);
    info!("Verified received data:\n{received_string}",);

    Ok(())
}

/// Render redacted bytes as `🙈`.
fn bytes_to_redacted_string(bytes: &[u8]) -> Result<String, Error> {
    Ok(String::from_utf8(bytes.to_vec())
        .map_err(|err| anyhow!("Failed to parse bytes to redacted string: {err}"))?
        .replace('\0', "🙈"))
}
