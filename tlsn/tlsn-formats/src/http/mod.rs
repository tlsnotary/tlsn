//! Tooling for working with HTTP data.

mod commit;

pub use commit::{DefaultHttpCommitter, HttpCommit, HttpCommitError};

#[doc(hidden)]
pub use spansy::http;

pub use http::{
    parse_request, parse_response, Body, BodyContent, Header, HeaderName, HeaderValue, Method,
    Reason, Request, RequestLine, Requests, Response, Responses, Status, Target,
};
use tlsn_core::Transcript;

/// The kind of HTTP message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageKind {
    /// An HTTP request.
    Request,
    /// An HTTP response.
    Response,
}

/// An HTTP transcript.
#[derive(Debug)]
pub struct HttpTranscript {
    /// The requests sent to the server.
    pub requests: Vec<Request>,
    /// The responses received from the server.
    pub responses: Vec<Response>,
}

impl HttpTranscript {
    /// Parses the HTTP transcript from the provided transcripts.
    pub fn parse(transcript: &Transcript) -> Result<Self, spansy::ParseError> {
        let requests = Requests::new(transcript.sent().clone()).collect::<Result<Vec<_>, _>>()?;
        let responses =
            Responses::new(transcript.received().clone()).collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            requests,
            responses,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tlsn_core::{
        substring::{
            SubstringCommitConfigBuilder, SubstringCommitmentKind, SubstringProofConfigBuilder,
        },
        transcript::SubsequenceIdx,
        Direction, Transcript,
    };
    use utils::range::ToRangeSet;

    use crate::json::JsonValue;

    static TX: &[u8] = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n\
    POST /hello HTTP/1.1\r\nHost: localhost\r\nContent-Length: 44\r\nContent-Type: application/json\r\n\r\n\
    {\"foo\": \"bar\", \"bazz\": 123, \"buzz\": [1,\"5\"]}";
    static RX: &[u8] =
        b"HTTP/1.1 200 OK\r\nCookie: very-secret-cookie\r\nContent-Length: 14\r\nContent-Type: application/json\r\n\r\n\
    {\"foo\": \"bar\"}\r\n\
    HTTP/1.1 200 OK\r\nContent-Length: 14\r\nContent-Type: text/plain\r\n\r\n\
    Hello World!!!";

    #[test]
    fn test_http_commit() {
        let transcript = Transcript::new(TX, RX);

        let mut builder = SubstringCommitConfigBuilder::new(&transcript);
        builder.default_kind(SubstringCommitmentKind::Encoding);

        let transcript = HttpTranscript::parse(&transcript).unwrap();

        let mut committer = DefaultHttpCommitter::default();
        committer
            .commit_transcript(&mut builder, &transcript)
            .unwrap();

        let config = builder.build().unwrap();

        // Path
        assert!(config
            .iter_encoding()
            .find(|&idx| idx == &SubsequenceIdx::new(Direction::Sent, 4..5).unwrap())
            .is_some());

        // Host header
        assert!(config
            .iter_encoding()
            .find(|&idx| idx == &SubsequenceIdx::new(Direction::Sent, 16..33).unwrap())
            .is_some());

        // foo value
        assert!(config
            .iter_encoding()
            .find(|&idx| idx == &SubsequenceIdx::new(Direction::Sent, 137..140).unwrap())
            .is_some());

        // Cookie header
        assert!(config
            .iter_encoding()
            .find(|&idx| idx == &SubsequenceIdx::new(Direction::Received, 17..45).unwrap())
            .is_some());

        // Body
        assert!(config
            .iter_encoding()
            .find(|&idx| idx == &SubsequenceIdx::new(Direction::Received, 180..194).unwrap())
            .is_some());
    }

    #[test]
    fn test_http_prove() {
        let transcript = Transcript::new(TX, RX);

        let mut builder = SubstringProofConfigBuilder::new(&transcript);

        let transcript = HttpTranscript::parse(&transcript).unwrap();

        let req_0 = &transcript.requests[0];
        let req_1 = &transcript.requests[1];
        let BodyContent::Json(JsonValue::Object(req_1_body)) =
            &req_1.body.as_ref().unwrap().content
        else {
            unreachable!();
        };
        let resp_0 = &transcript.responses[0];
        let resp_1 = &transcript.responses[1];

        builder
            .reveal_sent(&req_0.without_data())
            .unwrap()
            .reveal_sent(&req_0.request.target)
            .unwrap()
            .reveal_sent(req_0.headers_with_name("host").next().unwrap())
            .unwrap();

        builder
            .reveal_sent(&req_1.without_data())
            .unwrap()
            .reveal_sent(&req_1_body.without_pairs())
            .unwrap()
            .reveal_sent(req_1_body.get("bazz").unwrap())
            .unwrap();

        builder
            .reveal_recv(&resp_0.without_data())
            .unwrap()
            .reveal_recv(resp_0.headers_with_name("cookie").next().unwrap())
            .unwrap();

        builder
            .reveal_recv(&resp_1.without_data())
            .unwrap()
            .reveal_recv(resp_1.body.as_ref().unwrap())
            .unwrap();

        let config = builder.build().unwrap();

        assert!(config
            .iter()
            .find(|&idx| idx
                == &SubsequenceIdx::new(Direction::Sent, req_0.without_data().to_range_set())
                    .unwrap())
            .is_some());

        assert!(config
            .iter()
            .find(|&idx| idx
                == &SubsequenceIdx::new(Direction::Sent, req_0.request.target.to_range_set())
                    .unwrap())
            .is_some());

        assert!(config
            .iter()
            .find(|&idx| idx
                == &SubsequenceIdx::new(
                    Direction::Sent,
                    req_0
                        .headers_with_name("host")
                        .next()
                        .unwrap()
                        .to_range_set()
                )
                .unwrap())
            .is_some());

        assert!(config
            .iter()
            .find(|&idx| idx
                == &SubsequenceIdx::new(Direction::Sent, req_1.without_data().to_range_set())
                    .unwrap())
            .is_some());

        assert!(config
            .iter()
            .find(|&idx| idx
                == &SubsequenceIdx::new(Direction::Sent, req_1_body.without_pairs().to_range_set())
                    .unwrap())
            .is_some());

        assert!(config
            .iter()
            .find(|&idx| idx
                == &SubsequenceIdx::new(
                    Direction::Sent,
                    req_1_body.get("bazz").unwrap().to_range_set()
                )
                .unwrap())
            .is_some());

        assert!(config
            .iter()
            .find(|&idx| idx
                == &SubsequenceIdx::new(Direction::Received, resp_0.without_data().to_range_set())
                    .unwrap())
            .is_some());

        assert!(config
            .iter()
            .find(|&idx| idx
                == &SubsequenceIdx::new(
                    Direction::Received,
                    resp_0
                        .headers_with_name("cookie")
                        .next()
                        .unwrap()
                        .to_range_set()
                )
                .unwrap())
            .is_some());

        assert!(config
            .iter()
            .find(|&idx| idx
                == &SubsequenceIdx::new(Direction::Received, resp_1.without_data().to_range_set())
                    .unwrap())
            .is_some());

        assert!(config
            .iter()
            .find(|&idx| idx
                == &SubsequenceIdx::new(
                    Direction::Received,
                    resp_1.body.as_ref().unwrap().to_range_set()
                )
                .unwrap())
            .is_some());
    }
}
