use mc_sgx_dcap_types::{QlError, Quote3};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    fs::File,
    io::{self, Read},
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
            QuoteError::IoError(err) => write!(f, "IoError: {err:?}"),
            QuoteError::IntelQuoteLibrary(err) => {
                write!(f, "IntelQuoteLibrary: {err}")
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
async fn gramine_quote(public_key: Vec<u8>) -> Result<Quote, QuoteError> {
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
    fs::write("/dev/attestation/user_report_data", public_key)?;

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

pub async fn quote(public_key: Vec<u8>) -> Quote {
    //// tee-detection logic will live here, for now its only gramine-sgx
    match gramine_quote(public_key).await {
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
