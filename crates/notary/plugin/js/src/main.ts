import { PluginVerifierConfig, VerifierOutput } from "./pdk";

const SERVER_DOMAIN = "raw.githubusercontent.com";

/**
 * Returns the verifier configuration.
 * The configuration is used to initialize the verifier in the host.
 *
 * @returns {PluginVerifierConfig}
 */
export function configImpl(): PluginVerifierConfig {
  console.log("Composing verifier configuration...");
  return new PluginVerifierConfig();
}

/**
 * Verifies the output from the TLS verifier.
 * This function is called after the MPC-TLS verification is complete
 * and allows the plugin to perform custom verification logic.
 *
 * @param {VerifierOutput} input -
 */
export function verifyImpl(input: VerifierOutput) {
  console.log("Starting verification...");
  const { serverName, transcript, transcriptCommitments } = input;

  console.log(
    "Transcript commitments:",
    JSON.stringify(transcriptCommitments, null, 2),
  );

  if (!transcript) {
    throw new Error("prover should have revealed transcript data");
  }

  if (!serverName) {
    throw new Error("prover should have revealed server name");
  }

  // Check sent data: check host.
  console.log("Starting sent data verification...");
  const sent = new Uint8Array(transcript.sent);
  const sentData = new TextDecoder().decode(sent);

  if (!sentData.includes(SERVER_DOMAIN)) {
    throw new Error(`Verification failed: Expected host ${SERVER_DOMAIN}`);
  }

  // Check received data: check json and version number.
  console.log("Starting received data verification...");
  const received = new Uint8Array(transcript.received);
  const response = new TextDecoder().decode(received);

  if (!response.includes("123 Elm Street")) {
    throw new Error("Verification failed: missing data in received data");
  }

  // Check Session info: server name.
  if (serverName !== SERVER_DOMAIN) {
    throw new Error("Verification failed: server name mismatches");
  }

  const sentString = bytesToRedactedString(sent);
  const receivedString = bytesToRedactedString(received);

  console.log(`Successfully verified ${SERVER_DOMAIN}`);
  console.log(`Verified sent data:\n${sentString}`);
  console.log(`Verified received data:\n${receivedString}`);
}

/**
 * Render redacted bytes as `🙈`.
 */
function bytesToRedactedString(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes).replace(/\0/g, "🙈");
}
