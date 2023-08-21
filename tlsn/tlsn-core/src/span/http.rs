//! Some support for redacting http using httparse

use super::SpanError;
use httparse::{Header, Request, Response, Status};
use std::{ops::Range, panic};

/// A Spanner for HTTP
pub struct HttpSpanner<'a, 'b> {
    body_start_request: Option<usize>,
    body_start_response: Option<usize>,
    request: Option<Request<'a, 'b>>,
    response: Option<Response<'a, 'b>>,
}

impl<'a, 'b> HttpSpanner<'a, 'b> {
    /// Create a new HttpSpanner
    pub fn new() -> Self {
        HttpSpanner {
            body_start_request: None,
            body_start_response: None,
            request: None,
            response: None,
        }
    }
}

impl<'a, 'b> Default for HttpSpanner<'a, 'b> {
    fn default() -> Self {
        HttpSpanner::new()
    }
}

impl<'a, 'b> HttpSpanner<'a, 'b> {
    /// Parse a http request
    pub fn parse_request(
        &mut self,
        headers: &'a mut [Header<'b>],
        bytes: &'b [u8],
    ) -> Result<(), SpanError> {
        let mut request = Request::new(headers);
        match request.parse(bytes) {
            Ok(Status::Complete(body_start)) => {
                self.body_start_request = Some(body_start);
                self.request = Some(request);
                Ok(())
            }
            Ok(Status::Partial) => Err(SpanError::ParseError),
            Err(_) => Err(SpanError::ParseError),
        }
    }

    /// Parse a http response
    pub fn parse_response(
        &mut self,
        headers: &'a mut [Header<'b>],
        bytes: &'b [u8],
    ) -> Result<(), SpanError> {
        let mut response = Response::new(headers);
        match response.parse(bytes) {
            Ok(Status::Complete(body_start)) => {
                self.body_start_response = Some(body_start);
                self.response = Some(response);
                Ok(())
            }
            Ok(Status::Partial) => Err(SpanError::ParseError),
            Err(_) => Err(SpanError::ParseError),
        }
    }

    /// Return the byte offset where the request body starts
    pub fn body_start_request(&self) -> Option<usize> {
        self.body_start_request
    }

    /// Return the byte offset where the response body starts
    pub fn body_start_response(&self) -> Option<usize> {
        self.body_start_response
    }

    /// Return the byte range matching the value belonging to the specified header key in the
    /// request
    pub fn header_value_span_request(&self, key: &str, bytes: &[u8]) -> Option<Range<usize>> {
        let request = self.request.as_ref()?;
        let header = request.headers.iter().find(|h| h.name == key)?;
        Some(get_ptr_range(bytes, header.value))
    }

    /// Return the byte range matching the value belonging to the specified header key in the
    /// response
    pub fn header_value_span_response(&self, key: &str, bytes: &[u8]) -> Option<Range<usize>> {
        let request = self.response.as_ref()?;
        let header = request.headers.iter().find(|h| h.name == key)?;
        Some(get_ptr_range(bytes, header.value))
    }
}

fn get_ptr_range(whole: &[u8], part: &[u8]) -> Range<usize> {
    if part.as_ptr() < whole.as_ptr() {
        panic!("part is not a part of whole");
    }
    let start = unsafe { part.as_ptr().offset_from(whole.as_ptr()) as usize };
    let end = start + part.len();
    Range { start, end }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_REQUEST: &[u8] = b"\
                        GET /home.html HTTP/1.1\n\
                        Host: developer.mozilla.org\n\
                        User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:50.0) Gecko/20100101 Firefox/50.0\n\
                        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.\n\
                        Accept-Language: en-US,en;q=0.\n\
                        Accept-Encoding: gzip, deflate, b\n\
                        Referer: https://developer.mozilla.org/testpage.htm\n\
                        Connection: keep-alive\n\
                        Cache-Control: max-age=0\n\n\
                        Hello World!";

    const TEST_RESPONSE: &[u8] = b"\
                        HTTP/1.1 200 OK\n\
                        Date: Mon, 27 Jul 2009 12:28:53 GMT\n\
                        Server: Apache/2.2.14 (Win32)\n\
                        Last-Modified: Wed, 22 Jul 2009 19:15:56 GMT\n\
                        Content-Length: 88\n\
                        Content-Type: text/html\n\
                        Connection: Closed\n\n\
                        <html>\n\
                        <body>\n\
                        <h1>Hello, World!</h1>\n\
                        </body>\n\
                        </html>";

    #[test]
    fn test_parse_request() {
        let mut spanner = HttpSpanner::new();
        let mut headers = vec![httparse::EMPTY_HEADER; 8];
        spanner.parse_request(&mut headers, TEST_REQUEST).unwrap();
        assert_eq!(
            &TEST_REQUEST[spanner.body_start_request().unwrap()..],
            b"Hello World!"
        );
    }

    #[test]
    fn test_header_value_span_request() {
        let mut spanner = HttpSpanner::new();
        let mut headers = vec![httparse::EMPTY_HEADER; 8];
        spanner.parse_request(&mut headers, TEST_REQUEST).unwrap();
        assert_eq!(
            &TEST_REQUEST[spanner
                .header_value_span_request("Host", TEST_REQUEST)
                .unwrap()],
            b"developer.mozilla.org"
        );
    }

    #[test]
    fn test_parse_response() {
        let mut spanner = HttpSpanner::new();
        let mut headers = vec![httparse::EMPTY_HEADER; 6];
        spanner.parse_response(&mut headers, TEST_RESPONSE).unwrap();
        assert_eq!(
            &TEST_RESPONSE[spanner.body_start_response().unwrap()..],
            b"\
                <html>\n\
                <body>\n\
                <h1>Hello, World!</h1>\n\
                </body>\n\
                </html>"
        );
    }

    #[test]
    fn test_header_value_span_response() {
        let mut spanner = HttpSpanner::new();
        let mut headers = vec![httparse::EMPTY_HEADER; 6];
        spanner.parse_response(&mut headers, TEST_RESPONSE).unwrap();
        assert_eq!(
            &TEST_RESPONSE[spanner
                .header_value_span_response("Content-Type", TEST_RESPONSE)
                .unwrap()],
            b"text/html"
        );
    }
}
