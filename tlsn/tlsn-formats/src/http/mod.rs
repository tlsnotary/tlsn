//! Tooling for working with HTTP data.

mod body;
mod commitment;
mod parse;
mod proof;
mod session;

pub use body::{Body, BodyCommitmentBuilder, BodyProofBuilder};
pub use commitment::{
    HttpCommitmentBuilder, HttpCommitmentBuilderError, HttpRequestCommitmentBuilder,
    HttpResponseCommitmentBuilder,
};
pub use parse::{parse_body, parse_requests, parse_responses, ParseError};
pub use proof::{HttpProofBuilder, HttpProofBuilderError};
pub use session::NotarizedHttpSession;

use serde::{Deserialize, Serialize};
use spansy::Spanned;
use utils::range::{RangeDifference, RangeSet, RangeUnion};

static PUBLIC_HEADERS: &[&str] = &["content-length", "content-type"];

/// An HTTP request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request(pub(crate) spansy::http::Request);

impl Request {
    pub(crate) fn public_ranges(&self) -> RangeSet<usize> {
        let mut private_ranges = RangeSet::default();

        let path_range = self.0.path.range();

        private_ranges = private_ranges.union(&path_range);

        for header in &self.0.headers {
            let name = header.name.span().as_str().to_ascii_lowercase();
            let range = header.value.span().range();
            if !PUBLIC_HEADERS.contains(&name.as_str()) {
                private_ranges = private_ranges.union(&range);
            }
        }

        if let Some(body) = &self.0.body {
            private_ranges = private_ranges.union(&body.span().range());
        }

        self.0.span().range().difference(&private_ranges)
    }
}

/// An HTTP response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response(pub(crate) spansy::http::Response);

impl Response {
    pub(crate) fn public_ranges(&self) -> RangeSet<usize> {
        let mut private_ranges = RangeSet::default();

        for header in &self.0.headers {
            let name = header.name.span().as_str().to_ascii_lowercase();
            let range = header.value.span().range();
            if !PUBLIC_HEADERS.contains(&name.as_str()) {
                private_ranges = private_ranges.union(&range);
            }
        }

        if let Some(body) = &self.0.body {
            private_ranges = private_ranges.union(&body.span().range());
        }

        self.0.span().range().difference(&private_ranges)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use bytes::Bytes;
    use tlsn_core::{
        commitment::{CommitmentKind, TranscriptCommitmentBuilder},
        fixtures,
        proof::SubstringsProofBuilder,
        Direction, Transcript,
    };

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
        let mut transcript_commitment_builder = TranscriptCommitmentBuilder::new(
            fixtures::encoding_provider(TX, RX),
            TX.len(),
            RX.len(),
        );

        let requests = parse_requests(Bytes::copy_from_slice(TX)).unwrap();
        let responses = parse_responses(Bytes::copy_from_slice(RX)).unwrap();

        HttpCommitmentBuilder::new(&mut transcript_commitment_builder, &requests, &responses)
            .build()
            .unwrap();

        let commitments = transcript_commitment_builder.build().unwrap();

        // Path
        assert!(commitments
            .get_id_by_info(CommitmentKind::Blake3, (4..5).into(), Direction::Sent)
            .is_some());

        // Host
        assert!(commitments
            .get_id_by_info(CommitmentKind::Blake3, (22..31).into(), Direction::Sent)
            .is_some());
        // foo
        assert!(commitments
            .get_id_by_info(CommitmentKind::Blake3, (137..140).into(), Direction::Sent)
            .is_some());

        // Cookie
        assert!(commitments
            .get_id_by_info(CommitmentKind::Blake3, (25..43).into(), Direction::Received)
            .is_some());
        // Body
        assert!(commitments
            .get_id_by_info(
                CommitmentKind::Blake3,
                (180..194).into(),
                Direction::Received
            )
            .is_some());
    }

    #[test]
    fn test_http_prove() {
        let transcript_tx = Transcript::new(TX);
        let transcript_rx = Transcript::new(RX);

        let mut transcript_commitment_builder = TranscriptCommitmentBuilder::new(
            fixtures::encoding_provider(TX, RX),
            TX.len(),
            RX.len(),
        );

        let requests = parse_requests(Bytes::copy_from_slice(TX)).unwrap();
        let responses = parse_responses(Bytes::copy_from_slice(RX)).unwrap();

        HttpCommitmentBuilder::new(&mut transcript_commitment_builder, &requests, &responses)
            .build()
            .unwrap();

        let commitments = transcript_commitment_builder.build().unwrap();

        let spb = SubstringsProofBuilder::new(&commitments, &transcript_tx, &transcript_rx);

        let mut builder = HttpProofBuilder::new(spb, &commitments, &requests, &responses);

        let mut req_0 = builder.request(0).unwrap();

        req_0.path().unwrap();
        req_0.header("host").unwrap();

        let mut req_1 = builder.request(1).unwrap();

        req_1.path().unwrap();

        let BodyProofBuilder::Json(mut json) = req_1.body().unwrap() else {
            unreachable!();
        };

        json.path("bazz").unwrap();

        let mut resp_0 = builder.response(0).unwrap();

        resp_0.header("cookie").unwrap();

        assert!(matches!(resp_0.body().unwrap(), BodyProofBuilder::Json(_)));

        let mut resp_1 = builder.response(1).unwrap();

        let BodyProofBuilder::Unknown(mut unknown) = resp_1.body().unwrap() else {
            unreachable!();
        };

        unknown.all().unwrap();

        let proof = builder.build().unwrap();

        let header = fixtures::session_header(commitments.merkle_root(), TX.len(), RX.len());

        let (sent, recv) = proof.verify(&header).unwrap();

        assert_eq!(&sent.data()[4..5], b"/");
        assert_eq!(&sent.data()[22..31], b"localhost");
        assert_eq!(&sent.data()[151..154], b"123");

        assert_eq!(&recv.data()[25..43], b"very-secret-cookie");
        assert_eq!(&recv.data()[180..194], b"Hello World!!!");
    }

    #[test]
    fn test_http_commit_duplicate_headers_call_build() {
        let tx: &[u8] = b"GET / HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\n\
        Accept: application/xml\r\n\r\n";
        let rx: &[u8] = b"HTTP/1.1 200 OK\r\nSet-Cookie: lang=en; Path=/\r\n\
        Set-Cookie: fang=fen; Path=/\r\nContent-Length: 14\r\n\r\n{\"foo\": \"bar\"}";

        let mut transcript_commitment_builder = TranscriptCommitmentBuilder::new(
            fixtures::encoding_provider(tx, rx),
            tx.len(),
            rx.len(),
        );
        let requests = parse_requests(Bytes::copy_from_slice(tx)).unwrap();
        let responses = parse_responses(Bytes::copy_from_slice(rx)).unwrap();

        HttpCommitmentBuilder::new(&mut transcript_commitment_builder, &requests, &responses)
            .build()
            .unwrap();

        let commitments = transcript_commitment_builder.build().unwrap();

        // Path
        assert!(commitments
            .get_id_by_info(CommitmentKind::Blake3, (4..5).into(), Direction::Sent)
            .is_some());
        // Host
        assert!(commitments
            .get_id_by_info(CommitmentKind::Blake3, (22..31).into(), Direction::Sent)
            .is_some());

        // Set-Cookie 1
        assert!(commitments
            .get_id_by_info(CommitmentKind::Blake3, (29..44).into(), Direction::Received)
            .is_some());
        // Set-Cookie 2
        assert!(commitments
            .get_id_by_info(CommitmentKind::Blake3, (58..74).into(), Direction::Received)
            .is_some());
    }

    #[test]
    fn test_http_commit_duplicate_headers_call_headers() {
        let tx: &[u8] = b"GET / HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\n\
        Accept: application/xml\r\n\r\n";
        let rx: &[u8] = b"HTTP/1.1 200 OK\r\nSet-Cookie: lang=en; Path=/\r\n\
        Set-Cookie: fang=fen; Path=/\r\nContent-Length: 14\r\n\r\n{\"foo\": \"bar\"}";

        let mut transcript_commitment_builder = TranscriptCommitmentBuilder::new(
            fixtures::encoding_provider(tx, rx),
            tx.len(),
            rx.len(),
        );
        let requests = parse_requests(Bytes::copy_from_slice(tx)).unwrap();
        let responses = parse_responses(Bytes::copy_from_slice(rx)).unwrap();

        let mut http_builder =
            HttpCommitmentBuilder::new(&mut transcript_commitment_builder, &requests, &responses);

        let mut req_builder = http_builder.request(0).unwrap();
        req_builder.path().unwrap();
        req_builder.headers().unwrap();

        let mut resp_builder = http_builder.response(0).unwrap();
        resp_builder.headers().unwrap();

        let commitments = transcript_commitment_builder.build().unwrap();

        // Path
        assert!(commitments
            .get_id_by_info(CommitmentKind::Blake3, (4..5).into(), Direction::Sent)
            .is_some());
        // Host
        assert!(commitments
            .get_id_by_info(CommitmentKind::Blake3, (22..31).into(), Direction::Sent)
            .is_some());

        // Set-Cookie 1
        assert!(commitments
            .get_id_by_info(CommitmentKind::Blake3, (29..44).into(), Direction::Received)
            .is_some());
        // Set-Cookie 2
        assert!(commitments
            .get_id_by_info(CommitmentKind::Blake3, (58..74).into(), Direction::Received)
            .is_some());
    }
}
