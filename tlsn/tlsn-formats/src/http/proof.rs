use std::ops::Range;

use crate::http::{body::BodyProofBuilder, Body, Request, Response};
use spansy::Spanned;
use tlsn_core::{
    commitment::{CommitmentId, CommitmentKind, TranscriptCommitments},
    proof::{SubstringsProof, SubstringsProofBuilder, SubstringsProofBuilderError},
    Direction,
};

/// HTTP proof builder error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HttpProofBuilderError {
    /// Header is missing.
    #[error("header with name \"{0}\" does not exist.")]
    MissingHeader(String),
    /// Body proof error.
    #[error("body proof error: {0}")]
    Body(String),
    /// Missing commitment for value.
    #[error("missing commitment for {0}")]
    MissingCommitment(String),
    /// Substrings proof builder error.
    #[error("proof builder error: {0}")]
    Proof(#[from] SubstringsProofBuilderError),
}

/// Builder for proofs of data in an HTTP connection.
#[derive(Debug)]
pub struct HttpProofBuilder<'a, 'b> {
    builder: SubstringsProofBuilder<'b>,
    commitments: &'a TranscriptCommitments,
    requests: &'a [(Request, Option<Body>)],
    responses: &'a [(Response, Option<Body>)],
    built_requests: Vec<bool>,
    built_responses: Vec<bool>,
}

impl<'a, 'b> HttpProofBuilder<'a, 'b> {
    #[doc(hidden)]
    pub fn new(
        builder: SubstringsProofBuilder<'b>,
        commitments: &'a TranscriptCommitments,
        requests: &'a [(Request, Option<Body>)],
        responses: &'a [(Response, Option<Body>)],
    ) -> Self {
        Self {
            builder,
            commitments,
            requests,
            responses,
            built_requests: vec![false; requests.len()],
            built_responses: vec![false; responses.len()],
        }
    }

    /// Returns a proof builder for the given request, if it exists.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the request to build a proof for.
    pub fn request<'c>(&'c mut self, index: usize) -> Option<HttpRequestProofBuilder<'c, 'b>>
    where
        'a: 'c,
    {
        self.requests
            .get(index)
            .map(|request| HttpRequestProofBuilder {
                builder: &mut self.builder,
                commitments: self.commitments,
                request: &request.0,
                body: request.1.as_ref(),
                built: &mut self.built_requests[index],
                body_built: false,
            })
    }

    /// Returns a proof builder for the given response, if it exists.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the response to build a proof for.
    pub fn response<'c>(&'c mut self, index: usize) -> Option<HttpResponseProofBuilder<'c, 'b>>
    where
        'a: 'c,
    {
        self.responses
            .get(index)
            .map(|response| HttpResponseProofBuilder {
                builder: &mut self.builder,
                commitments: self.commitments,
                response: &response.0,
                body: response.1.as_ref(),
                built: &mut self.built_responses[index],
                body_built: false,
            })
    }

    /// Builds the HTTP transcript proof.
    pub fn build(mut self) -> Result<SubstringsProof, HttpProofBuilderError> {
        // Build any remaining request proofs
        for i in 0..self.requests.len() {
            if !self.built_requests[i] {
                self.request(i).unwrap().build()?;
            }
        }

        // Build any remaining response proofs
        for i in 0..self.responses.len() {
            if !self.built_responses[i] {
                self.response(i).unwrap().build()?;
            }
        }

        self.builder.build().map_err(From::from)
    }
}

#[derive(Debug)]
pub struct HttpRequestProofBuilder<'a, 'b> {
    builder: &'a mut SubstringsProofBuilder<'b>,
    commitments: &'a TranscriptCommitments,
    request: &'a Request,
    body: Option<&'a Body>,
    built: &'a mut bool,
    // TODO: this field will be used in the future to support advanced configurations
    // but for now we don't want to build the body proof unless it is specifically requested
    body_built: bool,
}

impl<'a, 'b> HttpRequestProofBuilder<'a, 'b> {
    /// Reveals the entirety of the request.
    ///
    /// # Arguments
    ///
    /// * `body` - Whether to reveal the entirety of the request body as well.
    pub fn all(&mut self, body: bool) -> Result<&mut Self, HttpProofBuilderError> {
        let id = self
            .commit_id(self.request.0.span().range())
            .ok_or_else(|| {
                HttpProofBuilderError::MissingCommitment("the entire request".to_string())
            })?;

        self.builder.reveal(id)?;

        if body && self.body.is_some() {
            self.body().unwrap().all()?;
        }

        Ok(self)
    }

    /// Reveals the path of the request.
    pub fn path(&mut self) -> Result<&mut Self, HttpProofBuilderError> {
        let id = self
            .commit_id(self.request.0.path.range())
            .ok_or_else(|| HttpProofBuilderError::MissingCommitment("path".to_string()))?;

        self.builder.reveal(id)?;

        Ok(self)
    }

    /// Reveals the value of the given header.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the header value to reveal.
    pub fn header(&mut self, name: &str) -> Result<&mut Self, HttpProofBuilderError> {
        let header = self
            .request
            .0
            .header(name)
            .ok_or_else(|| HttpProofBuilderError::MissingHeader(name.to_string()))?;

        let id = self.commit_id(header.value.span().range()).ok_or_else(|| {
            HttpProofBuilderError::MissingCommitment(format!("header \"{}\"", name))
        })?;

        self.builder.reveal(id)?;

        Ok(self)
    }

    /// Returns a proof builder for the request body, if it exists.
    pub fn body<'c>(&'c mut self) -> Option<BodyProofBuilder<'c, 'b>> {
        self.body.map(|body| {
            BodyProofBuilder::new(
                self.builder,
                self.commitments,
                body,
                Direction::Sent,
                &mut self.body_built,
            )
        })
    }

    /// Builds the HTTP request proof.
    pub fn build(self) -> Result<(), HttpProofBuilderError> {
        let public_id = self
            .commitments
            .get_id_by_info(
                CommitmentKind::Blake3,
                self.request.public_ranges(),
                Direction::Sent,
            )
            .ok_or_else(|| HttpProofBuilderError::MissingCommitment("public data".to_string()))?;

        self.builder.reveal(public_id)?;

        *self.built = true;

        Ok(())
    }

    fn commit_id(&self, range: Range<usize>) -> Option<CommitmentId> {
        // TODO: support different kinds of commitments
        self.commitments
            .get_id_by_info(CommitmentKind::Blake3, range.into(), Direction::Sent)
    }
}

#[derive(Debug)]
pub struct HttpResponseProofBuilder<'a, 'b: 'a> {
    builder: &'a mut SubstringsProofBuilder<'b>,
    commitments: &'a TranscriptCommitments,
    response: &'a Response,
    body: Option<&'a Body>,
    built: &'a mut bool,
    // TODO: this field will be used in the future to support advanced configurations
    // but for now we don't want to build the body proof unless it is specifically requested
    body_built: bool,
}

impl<'a, 'b> HttpResponseProofBuilder<'a, 'b> {
    /// Reveals the entirety of the response.
    ///
    /// # Arguments
    ///
    /// * `body` - Whether to reveal the entirety of the response body as well.
    pub fn all(&mut self, body: bool) -> Result<&mut Self, HttpProofBuilderError> {
        let id = self
            .commit_id(self.response.0.span().range())
            .ok_or_else(|| {
                HttpProofBuilderError::MissingCommitment("the entire response".to_string())
            })?;

        self.builder.reveal(id)?;

        if body && self.body.is_some() {
            self.body().unwrap().all()?;
        }

        Ok(self)
    }

    /// Reveals the value of the given header.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the header value to reveal.
    pub fn header(&mut self, name: &str) -> Result<&mut Self, HttpProofBuilderError> {
        let header = self
            .response
            .0
            .header(name)
            .ok_or_else(|| HttpProofBuilderError::MissingHeader(name.to_string()))?;

        let id = self.commit_id(header.value.span().range()).ok_or_else(|| {
            HttpProofBuilderError::MissingCommitment(format!("header \"{}\"", name))
        })?;

        self.builder.reveal(id)?;

        Ok(self)
    }

    /// Returns a proof builder for the response body, if it exists.
    pub fn body<'c>(&'c mut self) -> Option<BodyProofBuilder<'c, 'b>> {
        self.body.map(|body| {
            BodyProofBuilder::new(
                self.builder,
                self.commitments,
                body,
                Direction::Received,
                &mut self.body_built,
            )
        })
    }

    /// Builds the HTTP response proof.
    pub fn build(self) -> Result<(), HttpProofBuilderError> {
        let public_id = self
            .commitments
            .get_id_by_info(
                CommitmentKind::Blake3,
                self.response.public_ranges(),
                Direction::Received,
            )
            .ok_or_else(|| HttpProofBuilderError::MissingCommitment("public data".to_string()))?;

        self.builder.reveal(public_id)?;

        *self.built = true;

        Ok(())
    }

    fn commit_id(&self, range: Range<usize>) -> Option<CommitmentId> {
        // TODO: support different kinds of commitments
        self.commitments
            .get_id_by_info(CommitmentKind::Blake3, range.into(), Direction::Received)
    }
}
