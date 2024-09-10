use mc_sgx_dcap_types::QlError;
use serde::{Deserialize, Serialize};

use crate::signing::AttestationKey;
use p256::{ecdsa::SigningKey, PublicKey};
use pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use rand_chacha::{
    rand_core::{OsRng, SeedableRng},
    ChaCha20Rng,
};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    path::Path,
};
use tracing::{debug, error, instrument};
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

#[instrument(level = "debug", skip_all)]
async fn gramine_quote() -> Result<Quote, QuoteError> {
    //// Check if the the gramine pseudo-hardware exists
    if !Path::new("/dev/attestation/quote").exists() {
        error!("Failed to retrieve quote hardware");
        return Err(QuoteError::IntelQuoteLibrary(QlError::InterfaceUnavailable));
    }

    // Reading attestation type
    let mut attestation_file = File::open("/dev/attestation/attestation_type")?;
    let mut attestation_type = String::new();
    attestation_file.read_to_string(&mut attestation_type)?;
    debug!("Detected attestation type: {}", attestation_type);

    //// Writing 64 zero bytes to the gramine report pseudo-hardware `/dev/attestation/user_report_data`
    let mut report_data_file = OpenOptions::new()
        .write(true)
        .open("/dev/attestation/user_report_data")?;
    report_data_file.write_all(&[0u8; 64])?;

    //// Reading from the gramine quote pseudo-hardware `/dev/attestation/quote`
    let mut quote_file = File::open("/dev/attestation/quote")?;
    let mut quote = Vec::new();
    quote_file.read_to_end(&mut quote)?;

    if quote.len() < 432 {
        error!("Quote data is too short, expected at least 432 bytes");
        return Err(QuoteError::IntelQuoteLibrary(QlError::InvalidReport));
    }

    //// Extract mrenclave: enclave image,  and mrsigner: identity key bound to enclave
    //// https://github.com/intel/linux-sgx/blob/main/common/inc/sgx_quote.h
    let mrenclave = hex::encode(&quote[112..144]);
    let mrsigner = hex::encode(&quote[176..208]);

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

pub fn ephemeral_keypair() -> (AttestationKey, String) {
    let mut rng = ChaCha20Rng::from_rng(OsRng).expect("os rng err!");
    let signing_key = SigningKey::random(&mut rng);
    let pem_string = signing_key
        .clone()
        .to_pkcs8_pem(LineEnding::default())
        .expect("to pem");
    let attkey = AttestationKey::from_pkcs8_pem(&pem_string).expect("from pem");

    return (
        attkey,
        PublicKey::from(*signing_key.verifying_key()).to_string(),
    );
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
