use std::ops::Range;

use spansy::{
    http::{Request, Response},
    Spanned,
};
use tlsn_core::RedactedTranscript;
use utils::range::RangeSubset;

use crate::http::Body;

pub struct HttpVerifier<'a> {
    transcript_tx: &'a RedactedTranscript,
    transcript_rx: &'a RedactedTranscript,
    requests: &'a [(crate::http::Request, Option<Body>)],
    responses: &'a [(crate::http::Response, Option<Body>)],
}

impl<'a> HttpVerifier<'a> {
    #[doc(hidden)]
    pub fn new(
        transcript_tx: &'a RedactedTranscript,
        transcript_rx: &'a RedactedTranscript,
        requests: &'a [(crate::http::Request, Option<Body>)],
        responses: &'a [(crate::http::Response, Option<Body>)],
    ) -> Self {
        Self {
            transcript_tx,
            transcript_rx,
            requests,
            responses,
        }
    }

    /// Returns a verifier for the given request, if it exists.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the request to verify.
    pub fn request<'b: 'a>(&'b self, index: usize) -> Option<HttpRequestVerifier<'b>> {
        self.requests.get(index).map(|request| HttpRequestVerifier {
            transcript: self.transcript_tx,
            request: &request.0 .0,
            body: request.1.as_ref(),
        })
    }

    /// Returns a verifier for the given response, if it exists.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the response to verify.
    pub fn response<'b: 'a>(&'b self, index: usize) -> Option<HttpResponseVerifier<'b>> {
        self.responses
            .get(index)
            .map(|response| HttpResponseVerifier {
                transcript: self.transcript_rx,
                response: &response.0 .0,
                body: response.1.as_ref(),
            })
    }
}

#[derive(Debug)]
pub struct HttpRequestVerifier<'a> {
    transcript: &'a RedactedTranscript,
    request: &'a Request,
    body: Option<&'a Body>,
}

impl<'a> HttpRequestVerifier<'a> {
    /// Returns the path of the request, if it exists and was not redacted.
    pub fn path(&self) -> Option<&[u8]> {
        let range = self.request.path.range();
        if self.is_auth(&range) {
            Some(&self.transcript.data()[range])
        } else {
            None
        }
    }

    /// Returns the header value for the given name, if it exists and was not redacted.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the header to return.
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        let header = self.request.header(name)?;
        let range = header.value.span().range();

        if self.is_auth(&range) {
            Some(&self.transcript.data()[range])
        } else {
            None
        }
    }

    /// Returns whether the provided range has been authenticated.
    fn is_auth(&self, range: &Range<usize>) -> bool {
        range.is_subset(self.transcript.authed())
    }
}

#[derive(Debug)]
pub struct HttpResponseVerifier<'a> {
    transcript: &'a RedactedTranscript,
    response: &'a Response,
    body: Option<&'a Body>,
}

impl<'a> HttpResponseVerifier<'a> {
    /// Returns the status code of the response, if it exists and was not redacted.
    pub fn code(&self) -> Option<&[u8]> {
        let range = self.response.code.range();
        if self.is_auth(&range) {
            Some(&self.transcript.data()[range])
        } else {
            None
        }
    }

    /// Returns the reason phrase of the response, if it exists and was not redacted.
    pub fn reason(&self) -> Option<&[u8]> {
        let range = self.response.reason.range();
        if self.is_auth(&range) {
            Some(&self.transcript.data()[range])
        } else {
            None
        }
    }

    /// Returns the header value for the given name, if it exists and was not redacted.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the header to return.
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        let header = self.response.header(name)?;
        let range = header.value.span().range();

        if self.is_auth(&range) {
            Some(&self.transcript.data()[range])
        } else {
            None
        }
    }

    /// Returns whether the provided range has been authenticated.
    fn is_auth(&self, range: &Range<usize>) -> bool {
        range.is_subset(self.transcript.authed())
    }
}
