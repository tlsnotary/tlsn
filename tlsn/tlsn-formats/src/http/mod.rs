//! Tooling for working with HTTP data.

mod commit;
mod session;

pub use commit::{DefaultHttpCommitter, HttpCommit, HttpCommitError};
pub use session::NotarizedHttpSession;

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
    pub fn parse(tx: &Transcript, rx: &Transcript) -> Result<Self, spansy::ParseError> {
        let requests = Requests::new(tx.data().clone()).collect::<Result<Vec<_>, _>>()?;
        let responses = Responses::new(rx.data().clone()).collect::<Result<Vec<_>, _>>()?;

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
        commitment::{CommitmentKind, TranscriptCommitmentBuilder},
        fixtures,
        proof::SubstringsProofBuilder,
        Direction, Transcript,
    };

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
        let transcript_tx = Transcript::new(TX);
        let transcript_rx = Transcript::new(RX);

        let mut builder = TranscriptCommitmentBuilder::new(
            fixtures::encoding_provider(TX, RX),
            TX.len(),
            RX.len(),
        );

        let transcript = HttpTranscript::parse(&transcript_tx, &transcript_rx).unwrap();

        let mut committer = DefaultHttpCommitter::default();
        committer
            .commit_transcript(&mut builder, &transcript)
            .unwrap();

        let commitments = builder.build().unwrap();

        // Path
        assert!(commitments
            .get_id_by_info(CommitmentKind::Blake3, &(4..5).into(), Direction::Sent)
            .is_some());

        // Host header
        assert!(commitments
            .get_id_by_info(CommitmentKind::Blake3, &(16..33).into(), Direction::Sent)
            .is_some());
        // foo value
        assert!(commitments
            .get_id_by_info(CommitmentKind::Blake3, &(137..140).into(), Direction::Sent)
            .is_some());

        // Cookie header
        assert!(commitments
            .get_id_by_info(
                CommitmentKind::Blake3,
                &(17..45).into(),
                Direction::Received
            )
            .is_some());
        // Body
        assert!(commitments
            .get_id_by_info(
                CommitmentKind::Blake3,
                &(180..194).into(),
                Direction::Received
            )
            .is_some());
    }

    #[test]
    fn test_http_prove() {
        let transcript_tx = Transcript::new(TX);
        let transcript_rx = Transcript::new(RX);

        let mut builder = TranscriptCommitmentBuilder::new(
            fixtures::encoding_provider(TX, RX),
            TX.len(),
            RX.len(),
        );

        let transcript = HttpTranscript::parse(&transcript_tx, &transcript_rx).unwrap();

        let mut committer = DefaultHttpCommitter::default();
        committer
            .commit_transcript(&mut builder, &transcript)
            .unwrap();

        let commitments = builder.build().unwrap();

        let mut builder = SubstringsProofBuilder::new(&commitments, &transcript_tx, &transcript_rx);

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
            .reveal_sent(&req_0.without_data(), CommitmentKind::Blake3)
            .unwrap()
            .reveal_sent(&req_0.request.target, CommitmentKind::Blake3)
            .unwrap()
            .reveal_sent(
                req_0.headers_with_name("host").next().unwrap(),
                CommitmentKind::Blake3,
            )
            .unwrap();

        builder
            .reveal_sent(&req_1.without_data(), CommitmentKind::Blake3)
            .unwrap()
            .reveal_sent(&req_1_body.without_pairs(), CommitmentKind::Blake3)
            .unwrap()
            .reveal_sent(req_1_body.get("bazz").unwrap(), CommitmentKind::Blake3)
            .unwrap();

        builder
            .reveal_recv(&resp_0.without_data(), CommitmentKind::Blake3)
            .unwrap()
            .reveal_recv(
                resp_0.headers_with_name("cookie").next().unwrap(),
                CommitmentKind::Blake3,
            )
            .unwrap();

        builder
            .reveal_recv(&resp_1.without_data(), CommitmentKind::Blake3)
            .unwrap()
            .reveal_recv(resp_1.body.as_ref().unwrap(), CommitmentKind::Blake3)
            .unwrap();

        let proof = builder.build().unwrap();

        let header = fixtures::session_header(commitments.merkle_root(), TX.len(), RX.len());

        let (sent, recv) = proof.verify(&header).unwrap();

        assert_eq!(&sent.data()[4..5], b"/");
        assert_eq!(&sent.data()[22..31], b"localhost");
        assert_eq!(&sent.data()[151..154], b"123");

        assert_eq!(&recv.data()[25..43], b"very-secret-cookie");
        assert_eq!(&recv.data()[180..194], b"Hello World!!!");
    }
}
