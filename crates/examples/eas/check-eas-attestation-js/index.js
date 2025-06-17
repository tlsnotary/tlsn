import { ethers } from "ethers";
import { EAS, Offchain } from "@ethereum-attestation-service/eas-sdk";
import { readFileSync } from 'fs';

async function main() {
  const provider = new ethers.JsonRpcProvider(process.env.RPC_URL);
  const EAS_CONTRACT_ADDRESS = "0xC2679fBD37d54388Ce493F1DB75320D236e1815e";

  const eas = new EAS(EAS_CONTRACT_ADDRESS);
  eas.connect(provider);

  const serializedAttestation = readFileSync('../eas_attestation.json', 'utf8');
  const attestation = JSON.parse(serializedAttestation);

  const offchain = await eas.getOffchain();
  try {
    const signatureOk = await offchain.verifyOffchainAttestationSignature(attestation.signer, attestation.sig);
    console.log("Signature verification:", signatureOk)
  } catch (err) {
    console.error("Invalid or malformed offchain attestation:", err);
  }
}

main();
