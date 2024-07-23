use std::error::Error;

use spansy::Spanned;
use tlsn_core::{commitment::TranscriptCommitmentBuilder, Direction};

use crate::{
    http::{Body, BodyContent, Header, HttpTranscript, MessageKind, Request, Response, Target},
    json::{DefaultJsonCommitter, JsonCommit},
};

/// HTTP commitment error.
#[derive(Debug, thiserror::Error)]
#[error("http commit error: {msg}")]
pub struct HttpCommitError {
    idx: Option<usize>,
    record_kind: MessageKind,
    msg: String,
    #[source]
    source: Option<Box<dyn Error + Send + Sync>>,
}

impl HttpCommitError {
    /// Creates a new HTTP commitment error.
    ///
    /// # Arguments
    ///
    /// * `record_kind` - The kind of the record (request or response).
    /// * `msg` - The error message.
    pub fn new(record_kind: MessageKind, msg: impl Into<String>) -> Self {
        Self {
            idx: None,
            record_kind,
            msg: msg.into(),
            source: None,
        }
    }

    /// Creates a new HTTP commitment error with a source.
    ///
    /// # Arguments
    ///
    /// * `record_kind` - The kind of the record (request or response).
    /// * `msg` - The error message.
    /// * `source` - The source error.
    pub fn new_with_source<E>(record_kind: MessageKind, msg: impl Into<String>, source: E) -> Self
    where
        E: Into<Box<dyn Error + Send + Sync>>,
    {
        Self {
            idx: None,
            record_kind,
            msg: msg.into(),
            source: Some(source.into()),
        }
    }

    /// Sets the index of the request or response in the transcript.
    pub fn set_index(&mut self, idx: usize) {
        self.idx = Some(idx);
    }

    /// Returns the index of the request or response in the transcript, if set.
    pub fn index(&self) -> Option<usize> {
        self.idx
    }

    /// Returns the error message.
    pub fn msg(&self) -> &str {
        &self.msg
    }

    /// Returns the kind of record (request or response).
    pub fn record_kind(&self) -> &MessageKind {
        &self.record_kind
    }
}

/// An HTTP data committer.
#[allow(unused_variables)]
pub trait HttpCommit {
    /// Commits to an HTTP transcript.
    ///
    /// The default implementation commits to each request and response in the transcript separately.
    ///
    /// # Arguments
    ///
    /// * `builder` - The transcript commitment builder.
    /// * `transcript` - The transcript to commit.
    fn commit_transcript(
        &mut self,
        builder: &mut TranscriptCommitmentBuilder,
        transcript: &HttpTranscript,
    ) -> Result<(), HttpCommitError> {
        for request in &transcript.requests {
            self.commit_request(builder, Direction::Sent, request)?;
        }

        for response in &transcript.responses {
            self.commit_response(builder, Direction::Received, response)?;
        }

        Ok(())
    }

    /// Commits to a request.
    ///
    /// The default implementation commits to the request excluding the target, headers and body. Additionally,
    /// it commits to the target, headers and body separately.
    ///
    /// # Arguments
    ///
    /// * `builder` - The transcript commitment builder.
    /// * `direction` - The direction of the request (sent or received).
    /// * `request` - The request to commit to.
    fn commit_request(
        &mut self,
        builder: &mut TranscriptCommitmentBuilder,
        direction: Direction,
        request: &Request,
    ) -> Result<(), HttpCommitError> {
        builder.commit(request, direction).map_err(|e| {
            HttpCommitError::new_with_source(
                MessageKind::Request,
                "failed to commit to entire request",
                e,
            )
        })?;

        if !request.headers.is_empty() || request.body.is_some() {
            builder
                .commit(&request.without_data(), direction)
                .map_err(|e| {
                    HttpCommitError::new_with_source(
                        MessageKind::Request,
                        "failed to commit to request with excluded data",
                        e,
                    )
                })?;
        }

        self.commit_target(builder, direction, request, &request.request.target)?;

        for header in &request.headers {
            self.commit_request_header(builder, direction, request, header)?;
        }

        if let Some(body) = &request.body {
            self.commit_request_body(builder, direction, request, body)?;
        }

        Ok(())
    }

    /// Commits to a request target.
    ///
    /// The default implementation commits to the target as a whole.
    ///
    /// # Arguments
    ///
    /// * `builder` - The transcript commitment builder.
    /// * `direction` - The direction of the request (sent or received).
    /// * `request` - The parent request.
    /// * `target` - The target to commit to.
    fn commit_target(
        &mut self,
        builder: &mut TranscriptCommitmentBuilder,
        direction: Direction,
        request: &Request,
        target: &Target,
    ) -> Result<(), HttpCommitError> {
        builder.commit(target, direction).map_err(|e| {
            HttpCommitError::new_with_source(
                MessageKind::Request,
                "failed to commit to target in request",
                e,
            )
        })?;

        Ok(())
    }

    /// Commits to a request header.
    ///
    /// The default implementation commits to the entire header, and the header excluding the value.
    ///
    /// # Arguments
    ///
    /// * `builder` - The transcript commitment builder.
    /// * `direction` - The direction of the request (sent or received).
    /// * `parent` - The parent request.
    /// * `header` - The header to commit to.
    fn commit_request_header(
        &mut self,
        builder: &mut TranscriptCommitmentBuilder,
        direction: Direction,
        parent: &Request,
        header: &Header,
    ) -> Result<(), HttpCommitError> {
        builder.commit(header, direction).map_err(|e| {
            HttpCommitError::new_with_source(
                MessageKind::Request,
                format!("failed to commit to \"{}\" header", header.name.as_str()),
                e,
            )
        })?;

        if !header.value.span().is_empty() {
            builder
                .commit(&header.without_value(), direction)
                .map_err(|e| {
                    HttpCommitError::new_with_source(
                        MessageKind::Request,
                        format!(
                            "failed to commit to \"{}\" header excluding value",
                            header.name.as_str()
                        ),
                        e,
                    )
                })?;
        }

        Ok(())
    }

    /// Commits to a request body.
    ///
    /// The default implementation commits using the default implementation for the
    /// format type of the body. If the format of the body is unknown, it commits to the
    /// body as a whole.
    ///
    /// # Arguments
    ///
    /// * `builder` - The transcript commitment builder.
    /// * `direction` - The direction of the request (sent or received).
    /// * `parent` - The parent request.
    /// * `body` - The body to commit to.
    fn commit_request_body(
        &mut self,
        builder: &mut TranscriptCommitmentBuilder,
        direction: Direction,
        parent: &Request,
        body: &Body,
    ) -> Result<(), HttpCommitError> {
        match &body.content {
            BodyContent::Json(body) => {
                DefaultJsonCommitter::default()
                    .commit_value(builder, body, direction)
                    .map_err(|e| {
                        HttpCommitError::new_with_source(
                            MessageKind::Request,
                            "failed to commit to JSON body",
                            e,
                        )
                    })?;
            }
            body => {
                builder.commit(body, direction).map_err(|e| {
                    HttpCommitError::new_with_source(
                        MessageKind::Request,
                        "failed to commit to unknown content body",
                        e,
                    )
                })?;
            }
        }

        Ok(())
    }

    /// Commits to a response.
    ///
    /// The default implementation commits to the response excluding the headers and body. Additionally,
    /// it commits to the headers and body separately.
    ///
    /// # Arguments
    ///
    /// * `builder` - The transcript commitment builder.
    /// * `direction` - The direction of the response (sent or received).
    /// * `response` - The response to commit to.
    fn commit_response(
        &mut self,
        builder: &mut TranscriptCommitmentBuilder,
        direction: Direction,
        response: &Response,
    ) -> Result<(), HttpCommitError> {
        builder.commit(response, direction).map_err(|e| {
            HttpCommitError::new_with_source(
                MessageKind::Response,
                "failed to commit to entire response",
                e,
            )
        })?;

        if !response.headers.is_empty() || response.body.is_some() {
            builder
                .commit(&response.without_data(), direction)
                .map_err(|e| {
                    HttpCommitError::new_with_source(
                        MessageKind::Response,
                        "failed to commit to response excluding data",
                        e,
                    )
                })?;
        }

        for header in &response.headers {
            self.commit_response_header(builder, direction, response, header)?;
        }

        if let Some(body) = &response.body {
            self.commit_response_body(builder, direction, response, body)?;
        }

        Ok(())
    }

    /// Commits to a response header.
    ///
    /// The default implementation commits to the entire header, and the header excluding the value.
    ///
    /// # Arguments
    ///
    /// * `builder` - The transcript commitment builder.
    /// * `direction` - The direction of the response (sent or received).
    /// * `parent` - The parent response.
    /// * `header` - The header to commit to.
    fn commit_response_header(
        &mut self,
        builder: &mut TranscriptCommitmentBuilder,
        direction: Direction,
        parent: &Response,
        header: &Header,
    ) -> Result<(), HttpCommitError> {
        builder.commit(header, direction).map_err(|e| {
            HttpCommitError::new_with_source(
                MessageKind::Response,
                format!("failed to commit to \"{}\" header", header.name.as_str()),
                e,
            )
        })?;

        if !header.value.span().is_empty() {
            builder
                .commit(&header.without_value(), direction)
                .map_err(|e| {
                    HttpCommitError::new_with_source(
                        MessageKind::Response,
                        format!(
                            "failed to commit to \"{}\" header excluding value in response",
                            header.name.as_str()
                        ),
                        e,
                    )
                })?;
        }

        Ok(())
    }

    /// Commits to a response body.
    ///
    /// The default implementation commits using the default implementation for the
    /// format type of the body. If the format of the body is unknown, it commits to the
    /// body as a whole.
    ///
    /// # Arguments
    ///
    /// * `builder` - The transcript commitment builder.
    /// * `direction` - The direction of the response (sent or received).
    /// * `parent` - The parent response.
    /// * `body` - The body to commit to.
    fn commit_response_body(
        &mut self,
        builder: &mut TranscriptCommitmentBuilder,
        direction: Direction,
        parent: &Response,
        body: &Body,
    ) -> Result<(), HttpCommitError> {
        match &body.content {
            BodyContent::Json(body) => {
                DefaultJsonCommitter::default()
                    .commit_value(builder, body, direction)
                    .map_err(|e| {
                        HttpCommitError::new_with_source(
                            MessageKind::Response,
                            "failed to commit to JSON body",
                            e,
                        )
                    })?;
            }
            body => {
                builder.commit(body, direction).map_err(|e| {
                    HttpCommitError::new_with_source(
                        MessageKind::Request,
                        "failed to commit to unknown content body",
                        e,
                    )
                })?;
            }
        }

        Ok(())
    }
}

/// The default HTTP committer.
#[derive(Debug, Default, Clone)]
pub struct DefaultHttpCommitter {}

impl HttpCommit for DefaultHttpCommitter {}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;
    use spansy::http::{parse_request, parse_response};
    use tlsn_core::fixtures;

    #[rstest]
    #[case::get_empty(include_bytes!("../../tests/fixtures/http/request_get_empty"))]
    #[case::get_empty_header(include_bytes!("../../tests/fixtures/http/request_get_empty_header"))]
    #[case::get_with_header(include_bytes!("../../tests/fixtures/http/request_get_with_header"))]
    #[case::post_json(include_bytes!("../../tests/fixtures/http/request_post_json"))]
    fn test_http_default_commit_request(#[case] src: &'static [u8]) {
        let request = parse_request(src).unwrap();
        let mut committer = DefaultHttpCommitter::default();
        let mut builder =
            TranscriptCommitmentBuilder::new(fixtures::encoding_provider(src, &[]), src.len(), 0);

        committer
            .commit_request(&mut builder, Direction::Sent, &request)
            .unwrap();

        builder.build().unwrap();
    }

    #[rstest]
    #[case::empty(include_bytes!("../../tests/fixtures/http/response_empty"))]
    #[case::empty_header(include_bytes!("../../tests/fixtures/http/response_empty_header"))]
    #[case::json(include_bytes!("../../tests/fixtures/http/response_json"))]
    #[case::text(include_bytes!("../../tests/fixtures/http/response_text"))]
    fn test_http_default_commit_response(#[case] src: &'static [u8]) {
        let response = parse_response(src).unwrap();
        let mut committer = DefaultHttpCommitter::default();
        let mut builder =
            TranscriptCommitmentBuilder::new(fixtures::encoding_provider(&[], src), 0, src.len());

        committer
            .commit_response(&mut builder, Direction::Received, &response)
            .unwrap();

        builder.build().unwrap();
    }
}
