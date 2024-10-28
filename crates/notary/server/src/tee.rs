use k256::ecdsa::{SigningKey, VerifyingKey as PublicKey};
use mc_sgx_dcap_types::{QlError, Quote3};
use once_cell::sync::OnceCell;
use pkcs8::{EncodePrivateKey, LineEnding};
use rand_chacha::{
    rand_core::{OsRng, SeedableRng},
    ChaCha20Rng,
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    fs::File,
    io::{self, Read},
    path::Path,
};
use tracing::{debug, error, instrument};

lazy_static::lazy_static! {
    static ref SECP256K1_OID: simple_asn1::OID = simple_asn1::oid!(1, 3, 132, 0, 10);
    static ref ECDSA_OID: simple_asn1::OID = simple_asn1::oid!(1, 2, 840, 10045, 2, 1);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Quote {
    raw_quote: Option<String>,
    mrsigner: Option<String>,
    mrenclave: Option<String>,
    error: Option<String>,
}

impl Default for Quote {
    fn default() -> Quote {
        Quote {
            raw_quote: Some("".to_string()),
            mrsigner: None,
            mrenclave: None,
            error: None,
        }
    }
}

impl std::fmt::Debug for QuoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QuoteError::IoError(err) => write!(f, "IoError: {:?}", err),
            QuoteError::IntelQuoteLibrary(err) => {
                write!(f, "IntelQuoteLibrary: {}", err)
            }
        }
    }
}

impl From<io::Error> for QuoteError {
    fn from(err: io::Error) -> QuoteError {
        QuoteError::IoError(err)
    }
}

enum QuoteError {
    IoError(io::Error),
    IntelQuoteLibrary(QlError),
}

impl From<QlError> for QuoteError {
    fn from(src: QlError) -> Self {
        Self::IntelQuoteLibrary(src)
    }
}

static PUBLIC_KEY: OnceCell<PublicKey> = OnceCell::new();

fn pem_der_encode_with_asn1(public_point: &[u8]) -> String {
    use simple_asn1::*;

    let ecdsa_oid = ASN1Block::ObjectIdentifier(0, ECDSA_OID.clone());
    let secp256k1_oid = ASN1Block::ObjectIdentifier(0, SECP256K1_OID.clone());
    let alg_id = ASN1Block::Sequence(0, vec![ecdsa_oid, secp256k1_oid]);
    let key_bytes = ASN1Block::BitString(0, public_point.len() * 8, public_point.to_vec());

    let blocks = vec![alg_id, key_bytes];

    let der_out = simple_asn1::to_der(&ASN1Block::Sequence(0, blocks))
        .expect("Failed to encode ECDSA private key as DER");

    pem::encode(&pem::Pem {
        tag: "PUBLIC KEY".to_string(),
        contents: der_out,
    })
}

#[instrument(level = "debug", skip_all)]
async fn gramine_quote() -> Result<Quote, QuoteError> {
    //// Check if the the gramine pseudo-hardware exists
    if !Path::new("/dev/attestation/quote").exists() {
        return Ok(Quote::default());
    }

    // Reading attestation type
    let mut attestation_file = File::open("/dev/attestation/attestation_type")?;
    let mut attestation_type = String::new();
    attestation_file.read_to_string(&mut attestation_type)?;
    debug!("Detected attestation type: {}", attestation_type);

    // Read `/dev/attestation/my_target_info`
    let my_target_info = fs::read("/dev/attestation/my_target_info")?;

    // Write to `/dev/attestation/target_info`
    fs::write("/dev/attestation/target_info", my_target_info)?;

    //// Writing the pubkey to bind the instance to the hw (note: this is not
    //// mrsigner)
    fs::write(
        "/dev/attestation/user_report_data",
        PUBLIC_KEY
            .get()
            .expect("pub_key_get")
            .to_encoded_point(true)
            .as_bytes(),
    )?;

    //// Reading from the gramine quote pseudo-hardware `/dev/attestation/quote`
    let mut quote_file = File::open("/dev/attestation/quote")?;
    let mut quote = Vec::new();
    let _ = quote_file.read_to_end(&mut quote);
    //// todo: wire up Qlerror and drop .expect()
    let quote3 = Quote3::try_from(quote.as_ref()).expect("quote3 error");
    let mrenclave = quote3.app_report_body().mr_enclave().to_string();
    let mrsigner = quote3.app_report_body().mr_signer().to_string();

    debug!("mrenclave: {}", mrenclave);
    debug!("mrsigner: {}", mrsigner);

    //// Return the Quote struct with the extracted data
    Ok(Quote {
        raw_quote: Some(hex::encode(quote)),
        mrsigner: Some(mrsigner),
        mrenclave: Some(mrenclave),
        error: None,
    })
}

pub fn generate_ephemeral_keypair(notary_private: &str, notary_public: &str) {
    let mut rng = ChaCha20Rng::from_rng(OsRng).expect("os rng err!");
    let signing_key = SigningKey::random(&mut rng);
    let pem_string = signing_key
        .clone()
        .to_pkcs8_pem(LineEnding::LF)
        .expect("to pem");

    std::fs::write(notary_private, pem_string).expect("fs::write");

    let der = signing_key
        .verifying_key()
        .to_encoded_point(true)
        .to_bytes();
    let pem_spki_pub = pem_der_encode_with_asn1(&der);
    std::fs::write(notary_public, pem_spki_pub).expect("fs::write");
    let _ = PUBLIC_KEY
        .set(*signing_key.verifying_key())
        .map_err(|_| "Public key has already been set");
}

pub async fn quote() -> Quote {
    //// tee-detection logic will live here, for now its only gramine-sgx
    match gramine_quote().await {
        Ok(quote) => quote,
        Err(err) => {
            error!("Failed to retrieve quote: {:?}", err);
            match err {
                QuoteError::IoError(_) => Quote {
                    raw_quote: None,
                    mrsigner: None,
                    mrenclave: None,
                    error: Some("io".to_owned()),
                },
                QuoteError::IntelQuoteLibrary(_) => Quote {
                    raw_quote: None,
                    mrsigner: None,
                    mrenclave: None,
                    error: Some("hw".to_owned()),
                },
            }
        }
    }
}
