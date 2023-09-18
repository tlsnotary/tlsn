use std::ops::Range;

use crate::http::{body::BodyProofBuilder, Body};
use spansy::{
    http::{Request, Response},
    Spanned,
};
use tlsn_core::{
    commitment::{CommitmentId, CommitmentKind, TranscriptCommitments},
    proof::{SubstringsProofBuilder, SubstringsProofBuilderError},
    Direction,
};

/// An HTTP proof builder error.
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

#[derive(Debug)]
pub struct HttpProofBuilder<'a> {
    builder: &'a mut SubstringsProofBuilder<'a>,
    commitments: &'a TranscriptCommitments,
    requests: &'a [(crate::http::Request, Option<Body>)],
    responses: &'a [(crate::http::Response, Option<Body>)],
}

impl<'a> HttpProofBuilder<'a> {
    #[doc(hidden)]
    pub fn new(
        builder: &'a mut SubstringsProofBuilder<'a>,
        commitments: &'a TranscriptCommitments,
        requests: &'a [(crate::http::Request, Option<Body>)],
        responses: &'a [(crate::http::Response, Option<Body>)],
    ) -> Self {
        Self {
            builder,
            commitments,
            requests,
            responses,
        }
    }

    /// Returns a proof builder for the given request, if it exists.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the request to build a proof for.
    pub fn request<'b: 'a>(&'b mut self, index: usize) -> Option<HttpRequestProofBuilder<'b>> {
        self.requests
            .get(index)
            .map(|request| HttpRequestProofBuilder {
                builder: self.builder,
                commitments: self.commitments,
                request: &request.0 .0,
                body: request.1.as_ref(),
            })
    }

    /// Returns a proof builder for the given response, if it exists.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the response to build a proof for.
    pub fn response<'b: 'a>(&'b mut self, index: usize) -> Option<HttpResponseProofBuilder<'b>> {
        self.responses
            .get(index)
            .map(|response| HttpResponseProofBuilder {
                builder: self.builder,
                commitments: self.commitments,
                response: &response.0 .0,
                body: response.1.as_ref(),
            })
    }
}

#[derive(Debug)]
pub struct HttpRequestProofBuilder<'a> {
    builder: &'a mut SubstringsProofBuilder<'a>,
    commitments: &'a TranscriptCommitments,
    request: &'a Request,
    body: Option<&'a Body>,
}

impl<'a> HttpRequestProofBuilder<'a> {
    /// Reveals the entirety of the request.
    ///
    /// # Arguments
    ///
    /// * `body` - Whether to reveal the entirety of the request body as well.
    pub fn all(&mut self, body: bool) -> Result<(), HttpProofBuilderError> {
        let id = self.commit_id(self.request.span().range()).ok_or_else(|| {
            HttpProofBuilderError::MissingCommitment("the entire request".to_string())
        })?;

        self.builder.reveal(id)?;

        if body {
            todo!()
        }

        Ok(())
    }

    /// Reveals the path of the request.
    pub fn path(&mut self) -> Result<(), HttpProofBuilderError> {
        let id = self
            .commit_id(self.request.path.range())
            .ok_or_else(|| HttpProofBuilderError::MissingCommitment("path".to_string()))?;

        self.builder.reveal(id)?;

        Ok(())
    }

    /// Reveals the value of the given header.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the header value to reveal.
    pub fn header(&mut self, name: &str) -> Result<(), HttpProofBuilderError> {
        let header = self
            .request
            .header(name)
            .ok_or_else(|| HttpProofBuilderError::MissingHeader(name.to_string()))?;

        let id = self.commit_id(header.span().range()).ok_or_else(|| {
            HttpProofBuilderError::MissingCommitment(format!("header \"{}\"", name))
        })?;

        self.builder.reveal(id)?;

        Ok(())
    }

    /// Returns a proof builder for the request body, if it exists.
    pub fn body<'b: 'a>(&'b mut self) -> Option<BodyProofBuilder<'b>> {
        self.body.map(|body| {
            BodyProofBuilder::new(self.builder, self.commitments, body, Direction::Sent)
        })
    }

    fn commit_id(&self, range: Range<usize>) -> Option<CommitmentId> {
        // TODO: support different kinds of commitments
        self.commitments
            .get_id_by_info(CommitmentKind::Blake3, range.into(), Direction::Sent)
    }
}

#[derive(Debug)]
pub struct HttpResponseProofBuilder<'a> {
    builder: &'a mut SubstringsProofBuilder<'a>,
    commitments: &'a TranscriptCommitments,
    response: &'a Response,
    body: Option<&'a Body>,
}

impl<'a> HttpResponseProofBuilder<'a> {
    /// Reveals the entirety of the response.
    ///
    /// # Arguments
    ///
    /// * `body` - Whether to reveal the entirety of the request body as well.
    pub fn all(&mut self, body: bool) -> Result<(), HttpProofBuilderError> {
        let id = self
            .commit_id(self.response.span().range())
            .ok_or_else(|| {
                HttpProofBuilderError::MissingCommitment("the entire response".to_string())
            })?;

        self.builder.reveal(id)?;

        if body {
            todo!()
        }

        Ok(())
    }

    /// Reveals the status code of the response.
    pub fn code(&mut self) -> Result<(), HttpProofBuilderError> {
        let id = self
            .commit_id(self.response.code.range())
            .ok_or_else(|| HttpProofBuilderError::MissingCommitment("code".to_string()))?;

        self.builder.reveal(id)?;

        Ok(())
    }

    /// Reveals the reason phrase of the response.
    pub fn reason(&mut self) -> Result<(), HttpProofBuilderError> {
        let id = self
            .commit_id(self.response.reason.range())
            .ok_or_else(|| HttpProofBuilderError::MissingCommitment("code".to_string()))?;

        self.builder.reveal(id)?;

        Ok(())
    }

    /// Reveals the value of the given header.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the header value to reveal.
    pub fn header(&mut self, name: &str) -> Result<(), HttpProofBuilderError> {
        let header = self
            .response
            .header(name)
            .ok_or_else(|| HttpProofBuilderError::MissingHeader(name.to_string()))?;

        let id = self.commit_id(header.span().range()).ok_or_else(|| {
            HttpProofBuilderError::MissingCommitment(format!("header \"{}\"", name))
        })?;

        self.builder.reveal(id)?;

        Ok(())
    }

    /// Returns a proof builder for the response body, if it exists.
    pub fn body<'b: 'a>(&'b mut self) -> Option<BodyProofBuilder<'b>> {
        self.body.map(|body| {
            BodyProofBuilder::new(self.builder, self.commitments, body, Direction::Received)
        })
    }

    fn commit_id(&self, range: Range<usize>) -> Option<CommitmentId> {
        // TODO: support different kinds of commitments
        self.commitments
            .get_id_by_info(CommitmentKind::Blake3, range.into(), Direction::Received)
    }
}
