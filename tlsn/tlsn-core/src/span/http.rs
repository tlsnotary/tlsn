//! Some support for redacting http using httparse

use super::SpanError;
use httparse::{Header, Request, Response, Status};
use std::ops::Range;

/// A Spanner for HTTP
pub struct HttpSpanner<'a, 'b> {
    headers: Vec<Header<'b>>,
    body_start: usize,
    request: Option<Request<'a, 'b>>,
    response: Option<Response<'a, 'b>>,
}

impl<'a, 'b> HttpSpanner<'a, 'b> {
    /// Create a new HttpSpanner
    pub fn new(len: usize) -> Self {
        HttpSpanner {
            headers: vec![httparse::EMPTY_HEADER; len],
            body_start: 0,
            request: None,
            response: None,
        }
    }
}

impl<'a, 'b> HttpSpanner<'a, 'b> {
    /// Parse a http request
    pub fn parse_request(&'a mut self, bytes: &'b [u8]) -> Result<(), SpanError> {
        let mut request = Request::new(&mut self.headers[..]);
        match request.parse(bytes) {
            Ok(Status::Complete(body_start)) => {
                self.body_start = body_start;
                self.request = Some(request);
                Ok(())
            }
            Ok(Status::Partial) => Err(SpanError::ParseError),
            Err(_) => Err(SpanError::ParseError),
        }
    }

    /// Return the byte offset where the body starts
    pub fn body_start(&self) -> usize {
        self.body_start
    }

    /// Return the byte range matching the value belonging to the specified header key
    pub fn header_span(&self, key: &str, bytes: &[u8]) -> Option<Range<u32>> {
        let request = self.request.as_ref()?;
        let header = request.headers.iter().find(|h| h.name == key)?;
        Some(get_ptr_range(bytes, header.value))
    }
}

fn get_ptr_range(whole: &[u8], part: &[u8]) -> Range<u32> {
    let start = part.as_ptr() as u32 - whole.as_ptr() as u32;
    let end = start + part.len() as u32;
    Range { start, end }
}
