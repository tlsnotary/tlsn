#![no_main]

use libfuzzer_sys::fuzz_target;
use tlsn_core::{transcript::Transcript, Secrets};
use tlsn_formats::http::HttpTranscript;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Try to deserialize the input as Secrets
    if let Ok(secrets) = bincode::deserialize::<Secrets>(data) {
        // Get the transcript from secrets
        let transcript = secrets.transcript();
        
        // Try to parse the HTTP transcript
        let _result = HttpTranscript::parse(transcript);
    }
});
