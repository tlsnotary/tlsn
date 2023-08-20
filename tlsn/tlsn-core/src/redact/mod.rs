//! This module provides tooling for redaction of sensitive information in the notarized
//! transcripts before sending them to the verifier.

pub mod http;
pub mod json;

/// A trait which allows users to redact bytes from the transcript
///
/// After the traffic of a TLS session has been notarized, it is possible that the user wants to
/// redact certain information before sending it to the verifier. This trait allows arbitrary
/// redaction of bytes.
///
/// The user has to make sure that redacted bytes have not been committed to.
pub trait Redact {
    /// Redact bytes of the request
    fn redact_request(&mut self, request: &mut [u8]);
    /// Redact bytes of the response
    fn redact_response(&mut self, response: &mut [u8]);
}
