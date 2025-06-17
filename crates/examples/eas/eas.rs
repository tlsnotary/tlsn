use std::{
    env,
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

use ethers::{
    abi::Address,
    signers::{LocalWallet, Signer},
    types::H256,
};
use http_body_util::Empty;
use hyper::{body::Bytes, Request, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::instrument;

use tls_core::verify::WebPkiVerifier;
use tls_server_fixture::CA_CERT_DER;
use tlsn_common::config::{ProtocolConfig, ProtocolConfigValidator};
use tlsn_core::{
    transcript::PartialTranscript, CryptoProvider, ProveConfig, VerifierOutput, VerifyConfig,
};
use tlsn_prover::{Prover, ProverConfig};
use tlsn_server_fixture::DEFAULT_FIXTURE_PORT;
use tlsn_server_fixture_certs::SERVER_DOMAIN;
use tlsn_verifier::{Verifier, VerifierConfig};

const SECRET: &str = "random_auth_token";

// Maximum number of bytes that can be sent from prover to server.
const MAX_SENT_DATA: usize = 1 << 12;
// Maximum number of bytes that can be received by prover from server.
const MAX_RECV_DATA: usize = 1 << 14;

// The contract address of the EAS contract on Sepolia.
const EAS_ADDRESS: &str = "0xC2679fBD37d54388Ce493F1DB75320D236e1815e";
// The chain ID of the Sepolia network.
const EAS_CHAINID: u64 = 11155111;
// The schema for the EAS attestation.
const EAS_SCHEMA: &str = "0x938b5d03b0057688eef86d8101946311c4aaa740ffc39cef9bbfb6ce572a7198";

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let rpc_url = env::var("RPC_URL").expect("RPC_URL environment variable must be set");
    let sk = env::var("EAS_SK").expect("EAS_SK environment variable must be set");
    let server_host: String = env::var("SERVER_HOST").unwrap_or("127.0.0.1".into());
    let server_port: u16 = env::var("SERVER_PORT")
        .map(|port| port.parse().expect("port should be valid integer"))
        .unwrap_or(DEFAULT_FIXTURE_PORT);

    // We use SERVER_DOMAIN here to make sure it matches the domain in the test
    // server's certificate.
    let uri = format!("https://{SERVER_DOMAIN}:{server_port}/protected");
    let server_ip: IpAddr = server_host.parse().expect("Invalid IP address");
    let server_addr = SocketAddr::from((server_ip, server_port));

    // Connect prover and verifier.
    let (prover_socket, verifier_socket) = tokio::io::duplex(1 << 23);
    let prover = prover(prover_socket, &server_addr, &uri);
    let verifier = verifier(verifier_socket);
    let (_, transcript) = tokio::join!(prover, verifier);

    println!("Successfully verified {}", &uri);
    println!(
        "Verified sent data:\n{}",
        bytes_to_redacted_string(transcript.sent_unsafe())
    );
    println!(
        "Verified received data:\n{}",
        bytes_to_redacted_string(transcript.received_unsafe())
    );

    // Generate EAS attestation

    let signer = sk
        .parse::<LocalWallet>()
        .expect("Failed to parse LocalWallet")
        .with_chain_id(EAS_CHAINID);

    println!("Using EAS signer: {}", signer.address());

    let redacted_string = bytes_to_redacted_string(transcript.received_unsafe());
    let data = ethers::core::abi::encode(&[ethers::core::abi::Token::String(redacted_string)]);
    let verifying_contract = Address::from_str(EAS_ADDRESS).expect("Failed to parse EAS address");

    let attestation = eas::OfflineAttestationBuilder {
        schema: H256::from_str(EAS_SCHEMA).unwrap(),
        recipient: Address::zero(),
        time: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        expiration_time: Some(0),
        ref_uid: None,
        revocable: true,
        nonce: Some(0),
        data,
    }
    .generate(&signer, verifying_contract)
    .await
    .expect("Failed to generate attestation");

    std::fs::write(
        "eas_attestation.json",
        serde_json::to_string_pretty(&attestation).unwrap(),
    )
    .expect("Failed to write attestation to file");

    println!("EAS Attestation generated and saved to eas_attestation.json");

    // Timestamp the attestation using the EAS contract

    _ = eas::timestamp_attestation(&signer, &rpc_url, &attestation)
        .await
        .expect("Failed to timestamp attestation");
}

#[instrument(skip(verifier_socket))]
async fn prover<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
    verifier_socket: T,
    server_addr: &SocketAddr,
    uri: &str,
) {
    let uri = uri.parse::<Uri>().unwrap();
    assert_eq!(uri.scheme().unwrap().as_str(), "https");
    let server_domain = uri.authority().unwrap().host();

    // Create a crypto provider accepting the server-fixture's self-signed
    // root certificate.
    //
    // This is only required for offline testing with the server-fixture. In
    // production, use `CryptoProvider::default()` instead.
    let mut root_store = tls_core::anchors::RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();
    let crypto_provider = CryptoProvider {
        cert: WebPkiVerifier::new(root_store, None),
        ..Default::default()
    };

    // Create prover and connect to verifier.
    //
    // Perform the setup phase with the verifier.
    let prover = Prover::new(
        ProverConfig::builder()
            .server_name(server_domain)
            .protocol_config(
                ProtocolConfig::builder()
                    .max_sent_data(MAX_SENT_DATA)
                    .max_recv_data(MAX_RECV_DATA)
                    .build()
                    .unwrap(),
            )
            .crypto_provider(crypto_provider)
            .build()
            .unwrap(),
    )
    .setup(verifier_socket.compat())
    .await
    .unwrap();

    // Connect to TLS Server.
    let tls_client_socket = tokio::net::TcpStream::connect(server_addr).await.unwrap();

    // Pass server connection into the prover.
    let (mpc_tls_connection, prover_fut) =
        prover.connect(tls_client_socket.compat()).await.unwrap();

    // Wrap the connection in a TokioIo compatibility layer to use it with hyper.
    let mpc_tls_connection = TokioIo::new(mpc_tls_connection.compat());

    // Spawn the Prover to run in the background.
    let prover_task = tokio::spawn(prover_fut);

    // MPC-TLS Handshake.
    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(mpc_tls_connection)
            .await
            .unwrap();

    // Spawn the connection to run in the background.
    tokio::spawn(connection);

    // MPC-TLS: Send Request and wait for Response.
    let request = Request::builder()
        .uri(uri.clone())
        .header("Host", server_domain)
        .header("Connection", "close")
        .header("Authorization", format!("Bearer {}", SECRET))
        .method("GET")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let response = request_sender.send_request(request).await.unwrap();

    println!("Response: {:?}", response);
    assert!(response.status() == StatusCode::OK);

    // Create proof for the Verifier.
    let mut prover = prover_task.await.unwrap().unwrap();

    let mut builder = ProveConfig::builder(prover.transcript());

    // Reveal the DNS name.
    builder.server_identity();

    // Find the secret in the request.
    let pos = prover
        .transcript()
        .sent()
        .windows(SECRET.len())
        .position(|w| w == SECRET.as_bytes())
        .expect("the secret should be in the sent data");

    // Reveal everything except for the secret.
    builder.reveal_sent(&(0..pos)).unwrap();
    builder
        .reveal_sent(&(pos + SECRET.len()..prover.transcript().sent().len()))
        .unwrap();

    // Find the substring "Dick".
    let pos = prover
        .transcript()
        .received()
        .windows(4)
        .position(|w| w == b"Dick")
        .expect("the substring 'Dick' should be in the received data");

    // Reveal everything except for the substring.
    builder.reveal_recv(&(0..pos)).unwrap();
    builder
        .reveal_recv(&(pos + 4..prover.transcript().received().len()))
        .unwrap();

    let config = builder.build().unwrap();

    prover.prove(&config).await.unwrap();
    prover.close().await.unwrap();
}

#[instrument(skip(socket))]
async fn verifier<T: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    socket: T,
) -> PartialTranscript {
    // Set up Verifier.
    let config_validator = ProtocolConfigValidator::builder()
        .max_sent_data(MAX_SENT_DATA)
        .max_recv_data(MAX_RECV_DATA)
        .build()
        .unwrap();

    // Create a crypto provider accepting the server-fixture's self-signed
    // root certificate.
    //
    // This is only required for offline testing with the server-fixture. In
    // production, use `CryptoProvider::default()` instead.
    let mut root_store = tls_core::anchors::RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();
    let crypto_provider = CryptoProvider {
        cert: WebPkiVerifier::new(root_store, None),
        ..Default::default()
    };

    let verifier_config = VerifierConfig::builder()
        .protocol_config_validator(config_validator)
        .crypto_provider(crypto_provider)
        .build()
        .unwrap();
    let verifier = Verifier::new(verifier_config);

    // Receive authenticated data.
    let VerifierOutput {
        server_name,
        transcript,
        ..
    } = verifier
        .verify(socket.compat(), &VerifyConfig::default())
        .await
        .unwrap();

    let server_name = server_name.expect("prover should have revealed server name");
    let transcript = transcript.expect("prover should have revealed transcript data");

    // Check sent data.
    let sent = transcript.sent_unsafe().to_vec();
    let sent_data = String::from_utf8(sent.clone()).expect("Verifier expected sent data");
    sent_data
        .find(SERVER_DOMAIN)
        .unwrap_or_else(|| panic!("Verification failed: Expected host {}", SERVER_DOMAIN));

    // Check received data.
    let received = transcript.received_unsafe().to_vec();
    let response = String::from_utf8(received.clone()).expect("Verifier expected received data");
    response
        .find("John Doe")
        .unwrap_or_else(|| panic!("Expected valid data from {}", SERVER_DOMAIN));

    // Check Session info: server name.
    assert_eq!(server_name.as_str(), SERVER_DOMAIN);

    transcript
}

/// Render redacted bytes as `🙈`.
fn bytes_to_redacted_string(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec())
        .unwrap()
        .replace('\0', "🙈")
}

mod eas {

    use std::{collections::BTreeMap, str::FromStr};

    use super::*;
    use ethers::{
        abi::{Abi, Token},
        middleware::{
            gas_escalator::{Frequency, GeometricGasPrice},
            GasEscalatorMiddleware, MiddlewareBuilder, NonceManagerMiddleware, SignerMiddleware,
        },
        providers::{Http, Provider},
        signers::{Signer, Wallet},
        types::{
            transaction::eip712::{EIP712Domain, Eip712DomainType, TypedData},
            Address, Signature, H256, U256,
        },
        utils::{hex, keccak256, to_checksum},
    };
    use k256::ecdsa::SigningKey;
    use rand::RngCore;
    use serde::{Deserialize, Serialize};
    use serde_json::{Number, Value};

    // A signed offline attestation, which includes the signature and the signer's
    // address.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SignedOfflineAttestation {
        /// The attestation and its signature.
        pub sig: Sig,
        /// The address of the signer.
        pub signer: Address,
    }

    /// Represents the domain for EIP-712 typed data.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Domain {
        /// The name of the domain.
        pub name: String,
        /// The version of the domain.
        pub version: String,
        /// The chain ID of the domain.
        #[serde(rename = "chainId")]
        pub chain_id: String,
        /// The address of the verifying contract.
        #[serde(rename = "verifyingContract")]
        pub verifying_contract: String,
    }

    /// The Signed data and its signature for an offline attestation.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Sig {
        /// The version of the attestation.
        pub version: u16,
        /// The uid of the attestation, which is a hash of the attestation data.
        pub uid: String,

        /// The domain of the attestation.
        pub domain: Domain,
        #[serde(rename = "primaryType")]
        /// The primary type of the attestation.
        pub primary_type: String,
        /// The types that the attestation manages, which is a map of type names
        /// to their definitions.
        pub types: BTreeMap<String, Vec<Eip712DomainType>>,
        /// The message of the attestation, which is a map of field names to
        /// their values.
        pub message: BTreeMap<String, Value>,

        /// The secp256k1 signature of the attestation.
        pub signature: Signature,
    }

    /// Information to build an offline attestation.
    #[derive(Debug, Clone)]
    pub struct OfflineAttestationBuilder {
        pub schema: H256,
        pub recipient: Address,
        pub time: u64,
        pub expiration_time: Option<u64>,
        pub ref_uid: Option<H256>,
        pub revocable: bool,
        pub nonce: Option<u64>,
        pub data: Vec<u8>,
    }

    impl OfflineAttestationBuilder {
        /// Create and sign and offline attestation, returning a
        /// `SignedOfflineAttestation`.
        pub async fn generate<S: Signer>(
            &self,
            signer: &S,
            verifying_contract: Address,
        ) -> Result<SignedOfflineAttestation, <S as Signer>::Error> {
            let expiration_time = self.expiration_time.unwrap_or(0);

            let mut salt = [0u8; 32];
            rand::rng().fill_bytes(&mut salt);

            // the domain for the EIP-712 typed data.

            let domain = EIP712Domain {
                name: Some("EAS Attestation".to_string()),
                version: Some("0.26".to_string()),
                chain_id: Some(U256::from(signer.chain_id())),
                verifying_contract: Some(verifying_contract),
                salt: None,
            };

            // the typed data for the EIP-712 signature.

            let typed_data = TypedData {
                domain,
                primary_type: "Attest".to_string(),
                types: BTreeMap::from([(
                    "Attest".to_string(),
                    vec![
                        domtype("version", "uint16"),
                        domtype("schema", "bytes32"),
                        domtype("recipient", "address"),
                        domtype("time", "uint64"),
                        domtype("expirationTime", "uint64"),
                        domtype("revocable", "bool"),
                        domtype("refUID", "bytes32"),
                        domtype("data", "bytes"),
                        domtype("salt", "bytes32"),
                    ],
                )]),
                message: BTreeMap::from([
                    ("version".to_string(), Value::Number(Number::from(2))),
                    (
                        "schema".to_string(),
                        Value::String(format!("0x{}", hex::encode(self.schema))),
                    ),
                    (
                        "recipient".to_string(),
                        Value::String(format!("{:#x}", self.recipient)),
                    ),
                    ("time".to_string(), Value::String(self.time.to_string())),
                    (
                        "expirationTime".to_string(),
                        Value::String(expiration_time.to_string()),
                    ),
                    (
                        "refUID".to_string(),
                        Value::String(format!(
                            "0x{}",
                            hex::encode(self.ref_uid.unwrap_or_default())
                        )),
                    ),
                    ("revocable".to_string(), Value::Bool(self.revocable)),
                    (
                        "data".to_string(),
                        Value::String(format!("0x{}", hex::encode(&self.data))),
                    ),
                    (
                        "nonce".to_string(),
                        Value::Number(Number::from(self.nonce.unwrap_or(0))),
                    ),
                    (
                        "salt".to_string(),
                        Value::String(format!("0x{}", hex::encode(salt))),
                    ),
                ]),
            };

            // the unique identifier (uid) for the attestation, which is a hash of the ABI
            // encoded data.

            let uid = {
                let tokens = vec![
                    Token::FixedBytes(2u16.to_be_bytes().to_vec()),
                    Token::Bytes(format!("0x{}", hex::encode(self.schema)).into_bytes()),
                    Token::Address(self.recipient),
                    Token::Address(Address::zero()),
                    Token::FixedBytes(self.time.to_be_bytes().to_vec()),
                    Token::FixedBytes(expiration_time.to_be_bytes().to_vec()),
                    Token::Bool(self.revocable),
                    Token::FixedBytes(self.ref_uid.unwrap_or_default().0.to_vec()),
                    Token::Bytes(self.data.clone()),
                    Token::FixedBytes(salt.to_vec()),
                    Token::FixedBytes(0u32.to_be_bytes().to_vec()),
                ];

                let encoded = ethers::core::abi::encode_packed(&tokens).unwrap();
                keccak256(encoded)
            };

            // Sign the typed data using the signer's private key.
            let signature = signer.sign_typed_data(&typed_data).await?;

            // generate the signed offline attestation.
            let offline_attestation = SignedOfflineAttestation {
                sig: Sig {
                    version: 2,
                    uid: format!("0x{}", hex::encode(uid)),
                    domain: Domain {
                        name: typed_data.domain.name.unwrap(),
                        version: typed_data.domain.version.unwrap().to_string(),
                        chain_id: typed_data.domain.chain_id.unwrap().to_string(),
                        verifying_contract: to_checksum(
                            &typed_data.domain.verifying_contract.unwrap(),
                            None,
                        ),
                    },
                    primary_type: typed_data.primary_type,
                    types: typed_data.r#types,
                    message: typed_data.message,
                    signature,
                },
                signer: signer.address(),
            };

            Ok(offline_attestation)
        }
    }

    fn domtype(name: &str, type_name: &str) -> Eip712DomainType {
        Eip712DomainType {
            name: name.to_string(),
            r#type: type_name.to_string(),
        }
    }

    /// Timestamps an offline attestation by sending a transaction to the EAS
    /// contract.
    pub async fn timestamp_attestation(
        signer: &Wallet<SigningKey>,
        rpc_url: &str,
        attestation: &SignedOfflineAttestation,
    ) -> Result<H256, eyre::ErrReport> {
        // Set up signer

        let signer_address = signer.address();
        let escalator = GeometricGasPrice::new(1.125, 60_u64, None::<u64>);
        let provider = Provider::<Http>::try_from(rpc_url)?
            .wrap_into(|p| GasEscalatorMiddleware::new(p, escalator, Frequency::PerBlock))
            .wrap_into(|p| SignerMiddleware::new(p, signer.clone()))
            .wrap_into(|p| NonceManagerMiddleware::new(p, signer_address)); // Outermost layer

        // Read ABI and create contract instance

        let abi: Abi = serde_json::from_str(include_str!("eas.abi"))?;
        let contract = ethers::contract::Contract::new(
            EAS_ADDRESS.parse::<Address>().unwrap(),
            abi,
            provider.into(),
        );

        // Call Timestamp(bytes32 uid) method

        let uid =
            H256::from_str(&attestation.sig.uid).map_err(|_| eyre::eyre!("Invalid UID format"))?;

        let method = contract.method::<_, H256>("timestamp", uid)?;
        let pending_tx = method.send().await?;

        // Wait for transaction confirmation

        println!("EAS Timestamping attestation: {:?}", pending_tx);

        let receipt = pending_tx
            .confirmations(1)
            .await?
            .ok_or_else(|| eyre::eyre!("Transaction receipt not found"))?;

        println!(
            "EAS Attestation timestamped: {:?}",
            receipt.transaction_hash
        );

        Ok(receipt.transaction_hash)
    }
}
