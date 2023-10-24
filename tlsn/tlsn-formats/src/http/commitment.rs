use std::fmt::Debug;

use crate::http::{Body, BodyCommitmentBuilder, Request, Response};
use spansy::{http::Header, Spanned};
use tlsn_core::{
    commitment::{CommitmentId, TranscriptCommitmentBuilder, TranscriptCommitmentBuilderError},
    Direction,
};
use utils::range::{RangeSet, RangeSubset, RangeUnion};

use super::PUBLIC_HEADERS;

/// HTTP commitment builder error.
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

/// Builder for commitments to data in an HTTP connection.
#[derive(Debug)]
pub struct HttpCommitmentBuilder<'a> {
    builder: &'a mut TranscriptCommitmentBuilder,
    requests: &'a [(Request, Option<Body>)],
    responses: &'a [(Response, Option<Body>)],
    built_requests: Vec<bool>,
    built_responses: Vec<bool>,
}

impl<'a> HttpCommitmentBuilder<'a> {
    #[doc(hidden)]
    pub fn new(
        builder: &'a mut TranscriptCommitmentBuilder,
        requests: &'a [(Request, Option<Body>)],
        responses: &'a [(Response, Option<Body>)],
    ) -> Self {
        Self {
            builder,
            requests,
            responses,
            built_requests: vec![false; requests.len()],
            built_responses: vec![false; responses.len()],
        }
    }

    /// Returns a commitment builder for the request at the given index.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the request.
    #[must_use]
    pub fn request(&mut self, index: usize) -> Option<HttpRequestCommitmentBuilder<'_>> {
        self.requests.get(index).map(|request| {
            HttpRequestCommitmentBuilder::new(
                self.builder,
                &request.0,
                request.1.as_ref(),
                &mut self.built_requests[index],
            )
        })
    }

    /// Returns a commitment builder for the response at the given index.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the response.
    #[must_use]
    pub fn response(&mut self, index: usize) -> Option<HttpResponseCommitmentBuilder<'_>> {
        self.responses.get(index).map(|response| {
            HttpResponseCommitmentBuilder::new(
                self.builder,
                &response.0,
                response.1.as_ref(),
                &mut self.built_responses[index],
            )
        })
    }

    /// Builds commitments to the HTTP requests and responses.
    ///
    /// This automatically will commit to all header values which have no yet been committed.
    pub fn build(mut self) -> Result<(), HttpCommitmentBuilderError> {
        // Builds all request commitments
        for i in 0..self.requests.len() {
            if !self.built_requests[i] {
                self.request(i).unwrap().build()?;
            }
        }

        // Build all response commitments
        for i in 0..self.responses.len() {
            if !self.built_responses[i] {
                self.response(i).unwrap().build()?;
            }
        }

        Ok(())
    }
}

/// Builder for commitments to an HTTP request.
#[derive(Debug)]
pub struct HttpRequestCommitmentBuilder<'a> {
    builder: &'a mut TranscriptCommitmentBuilder,
    request: &'a Request,
    body: Option<&'a Body>,
    committed: RangeSet<usize>,
    built: &'a mut bool,
    body_built: bool,
}

impl<'a> HttpRequestCommitmentBuilder<'a> {
    pub(crate) fn new(
        builder: &'a mut TranscriptCommitmentBuilder,
        request: &'a Request,
        body: Option<&'a Body>,
        built: &'a mut bool,
    ) -> Self {
        Self {
            builder,
            request,
            body,
            committed: RangeSet::default(),
            built,
            body_built: false,
        }
    }

    /// Commits to the path of the request.
    pub fn path(&mut self) -> Result<CommitmentId, HttpCommitmentBuilderError> {
        let range = self.request.0.path.range();
        let id = self.builder.commit_sent(range.clone())?;

        self.committed = self.committed.union(&range);

        Ok(id)
    }

    /// Commits the value of the header with the given name.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the header value to commit.
    pub fn header(&mut self, name: &str) -> Result<CommitmentId, HttpCommitmentBuilderError> {
        let header = self
            .request
            .0
            .header(name)
            .ok_or(HttpCommitmentBuilderError::MissingHeader(name.to_string()))?;
        self.header_internal(header)
    }

    fn header_internal(
        &mut self,
        header: &Header,
    ) -> Result<CommitmentId, HttpCommitmentBuilderError> {
        let range = header.value.span().range();
        let id = self.builder.commit_sent(range.clone())?;

        self.committed = self.committed.union(&range);

        Ok(id)
    }

    /// Commits all request headers.
    ///
    /// Returns a vector of the names of the headers that were committed and their commitment IDs.
    pub fn headers(&mut self) -> Result<Vec<(String, CommitmentId)>, HttpCommitmentBuilderError> {
        let mut commitments = Vec::new();

        for header in &self.request.0.headers {
            let name = header.name.span().as_str().to_string();
            let id = self.header_internal(header)?;

            commitments.push((name, id));
        }

        Ok(commitments)
    }

    /// Returns a commitment builder for the request body if it exists.
    pub fn body(&mut self) -> Option<BodyCommitmentBuilder<'_>> {
        self.body.map(|body| {
            BodyCommitmentBuilder::new(self.builder, body, Direction::Sent, &mut self.body_built)
        })
    }

    /// Finishes building the request commitment.
    ///
    /// This commits to everything that has not already been committed, including a commitment
    /// to the format data of the request.
    pub fn build(mut self) -> Result<(), HttpCommitmentBuilderError> {
        // Commit to the path if it has not already been committed.
        let path_range = self.request.0.path.range();
        if !path_range.is_subset(&self.committed) {
            self.path()?;
        }

        // Commit to any headers that have not already been committed.
        for header in &self.request.0.headers {
            let name = header.name.span().as_str().to_ascii_lowercase();

            // Public headers can not be committed separately
            if PUBLIC_HEADERS.contains(&name.as_str()) {
                continue;
            }

            let range = header.value.span().range();
            if !range.is_subset(&self.committed) {
                self.header_internal(header)?;
            }
        }

        self.builder.commit_sent(self.request.public_ranges())?;

        if self.body.is_some() && !self.body_built {
            self.body().unwrap().build()?;
        }

        *self.built = true;

        Ok(())
    }
}

/// Builder for commitments to an HTTP response.
#[derive(Debug)]
pub struct HttpResponseCommitmentBuilder<'a> {
    builder: &'a mut TranscriptCommitmentBuilder,
    response: &'a Response,
    body: Option<&'a Body>,
    committed: RangeSet<usize>,
    built: &'a mut bool,
    body_built: bool,
}

impl<'a> HttpResponseCommitmentBuilder<'a> {
    pub(crate) fn new(
        builder: &'a mut TranscriptCommitmentBuilder,
        response: &'a Response,
        body: Option<&'a Body>,
        built: &'a mut bool,
    ) -> Self {
        Self {
            builder,
            response,
            body,
            committed: RangeSet::default(),
            built,
            body_built: false,
        }
    }

    /// Commits the value of the header with the given name.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the header value to commit.
    pub fn header(&mut self, name: &str) -> Result<CommitmentId, HttpCommitmentBuilderError> {
        let header = self
            .response
            .0
            .header(name)
            .ok_or(HttpCommitmentBuilderError::MissingHeader(name.to_string()))?;
        self.header_internal(header)
    }

    fn header_internal(
        &mut self,
        header: &Header,
    ) -> Result<CommitmentId, HttpCommitmentBuilderError> {
        self.builder
            .commit_recv(header.value.span().range())
            .map_err(From::from)
    }

    /// Commits all response headers.
    ///
    /// Returns a vector of the names of the headers that were committed and their commitment IDs.
    pub fn headers(&mut self) -> Result<Vec<(String, CommitmentId)>, HttpCommitmentBuilderError> {
        let mut commitments = Vec::new();

        for header in &self.response.0.headers {
            let name = header.name.span().as_str().to_string();
            let id = self.header_internal(header)?;

            commitments.push((name, id));
        }

        Ok(commitments)
    }

    /// Returns a commitment builder for the response body if it exists.
    pub fn body(&mut self) -> Option<BodyCommitmentBuilder<'_>> {
        self.body.map(|body| {
            BodyCommitmentBuilder::new(
                self.builder,
                body,
                Direction::Received,
                &mut self.body_built,
            )
        })
    }

    /// Finishes building the response commitment.
    ///
    /// This commits to everything that has not already been committed, including a commitment
    /// to the format data of the response.
    pub fn build(mut self) -> Result<(), HttpCommitmentBuilderError> {
        // Commit to any headers that have not already been committed.
        for header in &self.response.0.headers {
            let name = header.name.span().as_str().to_ascii_lowercase();

            // Public headers can not be committed separately
            if PUBLIC_HEADERS.contains(&name.as_str()) {
                continue;
            }

            let range = header.value.span().range();
            if !range.is_subset(&self.committed) {
                self.header_internal(header)?;
            }
        }

        self.builder.commit_recv(self.response.public_ranges())?;

        if self.body.is_some() && !self.body_built {
            self.body().unwrap().build()?;
        }

        *self.built = true;

        Ok(())
    }
}
