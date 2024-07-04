use elliptic_curve::pkcs8::DecodePrivateKey;
use futures::{AsyncRead, AsyncWrite};
use tlsn_verifier::tls::{Verifier, VerifierConfig};
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct PayoutRequest {
    payoutId: String,
    amount: String,
    currency: String,
    country: String,
    correspondent: String,
    recipient: Recipient,
    customerTimestamp: String,
    statementDescription: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Recipient {
    #[serde(rename = "type")]
    recipient_type: String,
    address: Address,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Address {
    value: String,
}

#[derive(Deserialize, Debug)]
pub struct PayoutCallback {
    amount: String,
    correspondent: String,
    country: String,
    created: String,
    currency: String,
    customerTimestamp: String,
    failureReason: Option<FailureReason>,
    payoutId: String,
    recipient: Recipient,
    statementDescription: String,
    status: String,
}

#[derive(Deserialize, Debug)]
pub struct FailureReason {
    failureCode: String,
    failureMessage: String,
}

#[derive(Deserialize, Debug)]
pub struct PayoutResponse {
    pub payoutId: String,
    pub status: String,
    pub amount: String,
    pub currency: String,
    pub country: String,
    pub correspondent: String,
    pub recipient: Recipient,
    pub customerTimestamp: String,
    pub statementDescription: String,
    pub created: String,
    pub receivedByRecipient: String,
    pub correspondentIds: CorrespondentIds,
    pub metadata: Metadata,
}

#[derive(Deserialize, Debug)]
pub struct CorrespondentIds {
    pub SOME_CORRESPONDENT_ID: String,
}

#[derive(Deserialize, Debug)]
pub struct Metadata {
    pub orderId: String,
    pub customerId: String,
}

/// Runs a simple Notary with the provided connection to the Prover.
pub async fn run_notary<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(conn: T) {
    // Load the notary signing key
    let signing_key_str = std::str::from_utf8(include_bytes!(
        "../../../notary/server/fixture/notary/notary.key"
    ))
    .unwrap();
    let signing_key = p256::ecdsa::SigningKey::from_pkcs8_pem(signing_key_str).unwrap();

    // Setup default config. Normally a different ID would be generated
    // for each notarization.
    let config = VerifierConfig::builder().id("example").build().unwrap();

    Verifier::new(config)
        .notarize::<_, p256::ecdsa::Signature>(conn, &signing_key)
        .await
        .unwrap();
}