mod pdk;

use anyhow::anyhow;
use extism_pdk::*;
use pdk::*;

const SERVER_DOMAIN: &str = "raw.githubusercontent.com";

// Returns the verifier configuration.
// The configuration is used to initialize the verifier in the host.
pub(crate) fn config() -> Result<types::PluginVerifierConfig, Error> {
    debug!("Composing verifier configuration...");
    Ok(types::PluginVerifierConfig::default())
}

// Verifies the output from the TLS verifier.
// This function is called after the MPC-TLS verification is complete
// and allows the plugin to perform custom verification logic.
pub(crate) fn verify(input: types::VerifierOutput) -> Result<(), Error> {
    debug!("Starting verification...");
    let types::VerifierOutput {
        server_name,
        transcript,
        transcript_commitments,
    } = input;

    debug!("Transcript commitments: {:?}", transcript_commitments);

    let transcript = transcript.ok_or(anyhow!("prover should have revealed transcript data"))?;
    let server_name = server_name.ok_or(anyhow!("prover should have revealed server name"))?;

    // Check sent data: check host.
    debug!("Starting sent data verification...");
    let sent: Vec<u8> = transcript
        .sent
        .into_iter()
        .map(|x| x.try_into().unwrap())
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
        .received
        .into_iter()
        .map(|x| x.try_into().unwrap())
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
