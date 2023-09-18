use tlsn_core::{
    commitment::{CommitmentId, TranscriptCommitmentBuilder, TranscriptCommitments},
    proof::SubstringsProofBuilder,
    Direction,
};

use crate::{
    http::HttpCommitmentBuilderError,
    json::{JsonBody, JsonCommitmentBuilder, JsonProofBuilder},
    unknown::{UnknownCommitmentBuilder, UnknownProofBuilder, UnknownSpan},
};

/// A body of an HTTP request or response
#[derive(Debug)]
#[non_exhaustive]
pub enum Body {
    /// A JSON body
    Json(JsonBody),
    /// A body with an unsupported content type
    Unknown(UnknownSpan),
}

#[derive(Debug)]
#[non_exhaustive]
pub enum BodyCommitmentBuilder<'a> {
    Json(JsonCommitmentBuilder<'a>),
    Unknown(UnknownCommitmentBuilder<'a>),
}

impl<'a> BodyCommitmentBuilder<'a> {
    pub(crate) fn new(
        builder: &'a mut TranscriptCommitmentBuilder,
        value: &'a Body,
        direction: Direction,
    ) -> Self {
        match value {
            Body::Json(body) => {
                BodyCommitmentBuilder::Json(JsonCommitmentBuilder::new(builder, &body.0, direction))
            }
            Body::Unknown(body) => BodyCommitmentBuilder::Unknown(UnknownCommitmentBuilder::new(
                builder, body, direction,
            )),
        }
    }

    /// Commits to the entirety of the body.
    pub fn all(&mut self) -> Result<CommitmentId, HttpCommitmentBuilderError> {
        match self {
            BodyCommitmentBuilder::Json(builder) => builder
                .all()
                .map_err(|e| HttpCommitmentBuilderError::Body(e.to_string())),
            BodyCommitmentBuilder::Unknown(builder) => builder
                .all()
                .map_err(|e| HttpCommitmentBuilderError::Body(e.to_string())),
        }
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum BodyProofBuilder<'a> {
    Json(JsonProofBuilder<'a>),
    Unknown(UnknownProofBuilder<'a>),
}

impl<'a> BodyProofBuilder<'a> {
    pub(crate) fn new(
        builder: &'a mut SubstringsProofBuilder<'a>,
        commitments: &'a TranscriptCommitments,
        value: &'a Body,
        direction: Direction,
    ) -> Self {
        match value {
            Body::Json(body) => BodyProofBuilder::Json(JsonProofBuilder::new(
                builder,
                commitments,
                &body.0,
                direction,
            )),
            Body::Unknown(body) => BodyProofBuilder::Unknown(UnknownProofBuilder::new(
                builder,
                commitments,
                body,
                direction,
            )),
        }
    }

    /// Reveals the entirety of the body.
    pub fn all(&mut self) -> Result<(), HttpCommitmentBuilderError> {
        match self {
            BodyProofBuilder::Json(builder) => builder
                .all()
                .map_err(|e| HttpCommitmentBuilderError::Body(e.to_string())),
            BodyProofBuilder::Unknown(builder) => builder
                .all()
                .map_err(|e| HttpCommitmentBuilderError::Body(e.to_string())),
        }
    }
}
