## Simple Interactive Verifier + Ethereum Attestation Service

This example is basically the `interactive` example adding the generation of Offline [EAS](https://attest.org/) Attestation and timestamping it. Please first understand the interactive example and [EAS](https://attest.org/) before getting into this example.

This demo:

- Runs a simple interactive session between a Prover and a Verifier
- Gets the redacted string of the response and generates an offline signed attestation of it. The attestation generated uses this [schema](https://sepolia.easscan.org/schema/view/0x938b5d03b0057688eef86d8101946311c4aaa740ffc39cef9bbfb6ce572a7198). It is stored in the `eas_attestation.json` local file.
- Timestamps the attestation (that is mainly calling the `timestamp` method in the EAS contract), the Tx of the transaction will be shown.
- You can verify the generated attestation with the provided `check-eas-attestation-js` example or using https://sepolia.easscan.org/tools.

To run this demo you need:

- Sepolia RPC provider URL
- [Ethereum address secret key](https://support.metamask.io/configure/accounts/how-to-export-an-accounts-private-key/) with some ether. 

This example fetches data from a local test server. To start this server, run:
```shell
PORT=4000 cargo run --bin tlsn-server-fixture
```
Next, run the interactive example with:
```shell
EAS_SK=<secret_key> RPC_URL=<rpc_url> SERVER_PORT=4000 cargo run --release --example eas
```
To view more detailed debug information, use the following command:
```shell
EAS_SK=<secret_key> RPC_URL=<rpc_url> RUST_LOG=debug,yamux=info,uid_mux=info SERVER_PORT=4000 cargo run --release --example eas
```

This will generate a signed EAS attestation, you can verify it by using the eas-sdk with:
```shell
cd check-eas-attestation-js
npm i
RPC_URL=<rpc_url> npm run start
```

