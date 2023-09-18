use std::fmt::Debug;

use crate::http::{Body, BodyCommitmentBuilder};
use spansy::{
    http::{Request, Response},
    Spanned,
};
use tlsn_core::{
    commitment::{CommitmentId, TranscriptCommitmentBuilder, TranscriptCommitmentBuilderError},
    Direction,
};

/// An HTTP commitment builder error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HttpCommitmentBuilderError {
    /// Header is missing.
    #[error("header with name \"{0}\" does not exist.")]
    MissingHeader(String),
    /// Body commitment error.
    #[error("body commitment error: {0}")]
    Body(String),
    /// Transcript commitment builder error.
    #[error("commitment builder error: {0}")]
    Commitment(#[from] TranscriptCommitmentBuilderError),
}

#[derive(Debug)]
pub struct HttpCommitmentBuilder<'a> {
    builder: &'a mut TranscriptCommitmentBuilder,
    requests: &'a [(crate::http::Request, Option<Body>)],
    responses: &'a [(crate::http::Response, Option<Body>)],
}

impl<'a> HttpCommitmentBuilder<'a> {
    #[doc(hidden)]
    pub fn new(
        builder: &'a mut TranscriptCommitmentBuilder,
        requests: &'a [(crate::http::Request, Option<Body>)],
        responses: &'a [(crate::http::Response, Option<Body>)],
    ) -> Self {
        Self {
            builder,
            requests,
            responses,
        }
    }

    /// Commits the entirety of the HTTP session.
    ///
    /// # Arguments
    ///
    /// * `body` - Whether to commit the entirety of each request and response body.
    pub fn all(&mut self, body: bool) -> Result<(), HttpCommitmentBuilderError> {
        self.requests(body)?;
        self.responses(body)?;

        Ok(())
    }

    /// Returns a commitment builder for the request at the given index.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the request.
    pub fn request(&mut self, index: usize) -> Option<HttpRequestCommitmentBuilder<'_>> {
        self.requests
            .get(index)
            .map(|request| HttpRequestCommitmentBuilder {
                builder: self.builder,
                request: &request.0 .0,
                body: request.1.as_ref(),
            })
    }

    /// Commits all requests.
    ///
    /// # Arguments
    ///
    /// * `body` - Whether to commit the entirety of each request body.
    pub fn requests(&mut self, body: bool) -> Result<(), HttpCommitmentBuilderError> {
        for idx in 0..self.requests.len() {
            let mut request = self.request(idx).unwrap();
            request.path()?;
            request.headers()?;

            if body {
                if let Some(mut body) = request.body() {
                    body.all()?;
                }
            }
        }

        Ok(())
    }

    /// Returns a commitment builder for the response at the given index.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the response.
    pub fn response(&mut self, index: usize) -> Option<HttpResponseCommitmentBuilder<'_>> {
        self.responses
            .get(index)
            .map(|response| HttpResponseCommitmentBuilder {
                builder: self.builder,
                response: &response.0 .0,
                body: response.1.as_ref(),
            })
    }

    /// Commits all responses.
    ///
    /// # Arguments
    ///
    /// * `body` - Whether to commit the entirety of each response body.
    pub fn responses(&mut self, body: bool) -> Result<(), HttpCommitmentBuilderError> {
        for idx in 0..self.responses.len() {
            let mut response = self.response(idx).unwrap();
            response.code()?;
            response.reason()?;
            response.headers()?;

            if body {
                if let Some(mut body) = response.body() {
                    body.all()?;
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct HttpRequestCommitmentBuilder<'a> {
    builder: &'a mut TranscriptCommitmentBuilder,
    request: &'a Request,
    body: Option<&'a Body>,
}

impl<'a> HttpRequestCommitmentBuilder<'a> {
    /// Commits the request path.
    pub fn path(&mut self) -> Result<CommitmentId, HttpCommitmentBuilderError> {
        self.builder
            .commit_sent(self.request.path.range())
            .map_err(From::from)
    }

    /// Commits the value of the header with the given name.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the header value to commit.
    pub fn header(&mut self, name: &str) -> Result<CommitmentId, HttpCommitmentBuilderError> {
        let header = self
            .request
            .header(name)
            .ok_or(HttpCommitmentBuilderError::MissingHeader(name.to_string()))?;

        self.builder
            .commit_sent(header.value.span().range())
            .map_err(From::from)
    }

    /// Commits all request headers.
    ///
    /// Returns a vector of the names of the headers that were committed and their commitment IDs.
    pub fn headers(&mut self) -> Result<Vec<(String, CommitmentId)>, HttpCommitmentBuilderError> {
        let mut commitments = Vec::new();

        for header in &self.request.headers {
            let name = header.name.span().as_str().to_string();
            let id = self.header(&name)?;

            commitments.push((name, id));
        }

        Ok(commitments)
    }

    /// Returns a commitment builder for the request body if it exists.
    pub fn body(&mut self) -> Option<BodyCommitmentBuilder<'_>> {
        self.body
            .map(|body| BodyCommitmentBuilder::new(self.builder, body, Direction::Sent))
    }
}

#[derive(Debug)]
pub struct HttpResponseCommitmentBuilder<'a> {
    builder: &'a mut TranscriptCommitmentBuilder,
    response: &'a Response,
    body: Option<&'a Body>,
}

impl<'a> HttpResponseCommitmentBuilder<'a> {
    /// Commits the response code.
    pub fn code(&mut self) -> Result<CommitmentId, HttpCommitmentBuilderError> {
        self.builder
            .commit_recv(self.response.code.range())
            .map_err(From::from)
    }

    /// Commits the response reason phrase.
    pub fn reason(&mut self) -> Result<CommitmentId, HttpCommitmentBuilderError> {
        self.builder
            .commit_recv(self.response.reason.range())
            .map_err(From::from)
    }

    /// Commits the value of the header with the given name.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the header value to commit.
    pub fn header(&mut self, name: &str) -> Result<CommitmentId, HttpCommitmentBuilderError> {
        let header = self
            .response
            .header(name)
            .ok_or(HttpCommitmentBuilderError::MissingHeader(name.to_string()))?;

        self.builder
            .commit_recv(header.value.span().range())
            .map_err(From::from)
    }

    /// Commits all response headers.
    ///
    /// Returns a vector of the names of the headers that were committed and their commitment IDs.
    pub fn headers(&mut self) -> Result<Vec<(String, CommitmentId)>, HttpCommitmentBuilderError> {
        let mut commitments = Vec::new();

        for header in &self.response.headers {
            let name = header.name.span().as_str().to_string();
            let id = self.header(&name)?;

            commitments.push((name, id));
        }

        Ok(commitments)
    }

    /// Returns a commitment builder for the response body if it exists.
    pub fn body(&mut self) -> Option<BodyCommitmentBuilder<'_>> {
        self.body
            .map(|body| BodyCommitmentBuilder::new(self.builder, body, Direction::Received))
    }
}
