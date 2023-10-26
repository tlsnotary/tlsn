use crate::http::{body::BodyProofBuilder, Body, Request, Response};
use spansy::Spanned;
use tlsn_core::{
    proof::{ProofBuilder, ProofBuilderError},
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
    Proof(#[from] ProofBuilderError),
}

/// Builder for proofs of data in an HTTP connection.
#[derive(Debug)]
pub struct HttpProofBuilder<'a, T> {
    builder: &'a mut dyn ProofBuilder<T>,
    requests: &'a [(Request, Option<Body>)],
    responses: &'a [(Response, Option<Body>)],
    built_requests: Vec<bool>,
    built_responses: Vec<bool>,
}

impl<'a, T: 'a> HttpProofBuilder<'a, T> {
    #[doc(hidden)]
    pub fn new(
        builder: &'a mut dyn ProofBuilder<T>,
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

    /// Returns a proof builder for the given request, if it exists.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the request to build a proof for.
    pub fn request(&mut self, index: usize) -> Option<HttpRequestProofBuilder<'_, T>> {
        self.requests
            .get(index)
            .map(|request| HttpRequestProofBuilder {
                builder: &mut *self.builder,
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
    pub fn response(&mut self, index: usize) -> Option<HttpResponseProofBuilder<'_, T>> {
        self.responses
            .get(index)
            .map(|response| HttpResponseProofBuilder {
                builder: &mut *self.builder,
                response: &response.0,
                body: response.1.as_ref(),
                built: &mut self.built_responses[index],
                body_built: false,
            })
    }

    /// Builds the HTTP transcript proof.
    pub fn build(mut self) -> Result<T, HttpProofBuilderError> {
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
pub struct HttpRequestProofBuilder<'a, T> {
    builder: &'a mut dyn ProofBuilder<T>,
    request: &'a Request,
    body: Option<&'a Body>,
    built: &'a mut bool,
    // TODO: this field will be used in the future to support advanced configurations
    // but for now we don't want to build the body proof unless it is specifically requested
    body_built: bool,
}

impl<'a, T> HttpRequestProofBuilder<'a, T> {
    /// Reveals the entirety of the request.
    ///
    /// # Arguments
    ///
    /// * `body` - Whether to reveal the entirety of the request body as well.
    pub fn all(&mut self, body: bool) -> Result<&mut Self, HttpProofBuilderError> {
        self.builder
            .reveal(self.request.0.span().range().into(), Direction::Sent)?;

        if body && self.body.is_some() {
            self.body().unwrap().all()?;
        }

        Ok(self)
    }

    /// Reveals the path of the request.
    pub fn path(&mut self) -> Result<&mut Self, HttpProofBuilderError> {
        self.builder
            .reveal(self.request.0.path.range().into(), Direction::Sent)?;

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

        self.builder
            .reveal(header.value.span().range().into(), Direction::Sent)?;

        Ok(self)
    }

    /// Returns a proof builder for the request body, if it exists.
    pub fn body(&mut self) -> Option<BodyProofBuilder<T>> {
        self.body.map(|body| {
            BodyProofBuilder::new(self.builder, body, Direction::Sent, &mut self.body_built)
        })
    }

    /// Builds the HTTP request proof.
    pub fn build(self) -> Result<(), HttpProofBuilderError> {
        self.builder
            .reveal(self.request.public_ranges(), Direction::Sent)?;

        *self.built = true;

        Ok(())
    }
}

#[derive(Debug)]
pub struct HttpResponseProofBuilder<'a, T> {
    builder: &'a mut dyn ProofBuilder<T>,
    response: &'a Response,
    body: Option<&'a Body>,
    built: &'a mut bool,
    // TODO: this field will be used in the future to support advanced configurations
    // but for now we don't want to build the body proof unless it is specifically requested
    body_built: bool,
}

impl<'a, T> HttpResponseProofBuilder<'a, T> {
    /// Reveals the entirety of the response.
    ///
    /// # Arguments
    ///
    /// * `body` - Whether to reveal the entirety of the response body as well.
    pub fn all(&mut self, body: bool) -> Result<&mut Self, HttpProofBuilderError> {
        self.builder
            .reveal(self.response.0.span().range().into(), Direction::Received)?;

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

        self.builder
            .reveal(header.value.span().range().into(), Direction::Received)?;

        Ok(self)
    }

    /// Returns a proof builder for the response body, if it exists.
    pub fn body(&mut self) -> Option<BodyProofBuilder<'_, T>> {
        self.body.map(|body| {
            BodyProofBuilder::new(
                self.builder,
                body,
                Direction::Received,
                &mut self.body_built,
            )
        })
    }

    /// Builds the HTTP response proof.
    pub fn build(self) -> Result<(), HttpProofBuilderError> {
        self.builder
            .reveal(self.response.public_ranges(), Direction::Received)?;

        *self.built = true;

        Ok(())
    }
}
