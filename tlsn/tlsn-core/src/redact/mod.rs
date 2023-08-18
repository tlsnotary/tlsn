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
    /// Redact the sent http request
    fn redact_sent_headers(&mut self, headers: &mut [u8]);
    ///Redact the body of the http request
    fn redact_sent_body(&mut self, body: &mut [u8]);
    /// Redact the http response
    fn redact_received_headers(&mut self, headers: &mut [u8]);
    ///Redact the body of the http response
    fn redact_received_body(&mut self, body: &mut [u8]);
}

/// A redaction implementation which does not redact anything
pub struct Identity;

impl Redact for Identity {
    fn redact_sent_headers(&mut self, _headers: &mut [u8]) {}
    fn redact_sent_body(&mut self, _body: &mut [u8]) {}
    fn redact_received_headers(&mut self, _headers: &mut [u8]) {}
    fn redact_received_body(&mut self, _body: &mut [u8]) {}
}
