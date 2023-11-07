use serde::{Deserialize, Serialize};

use tlsn_core::{
    commitment::{CommitmentId, TranscriptCommitmentBuilder, TranscriptCommitments},
    proof::SubstringsProofBuilder,
    Direction,
};

use crate::{
    http::{HttpCommitmentBuilderError, HttpProofBuilderError},
    json::{JsonBody, JsonCommitmentBuilder, JsonProofBuilder},
    unknown::{UnknownCommitmentBuilder, UnknownProofBuilder, UnknownSpan},
};

/// A body of an HTTP request or response
#[derive(Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Body {
    /// A JSON body
    Json(JsonBody),
    /// A body with an unsupported content type
    Unknown(UnknownSpan),
}

/// Builder for commitments to an HTTP body.
#[derive(Debug)]
#[non_exhaustive]
pub enum BodyCommitmentBuilder<'a> {
    /// Builder for commitments to a JSON body.
    Json(JsonCommitmentBuilder<'a>),
    /// Builder for commitments to a body with an unknown format.
    Unknown(UnknownCommitmentBuilder<'a>),
}

impl<'a> BodyCommitmentBuilder<'a> {
    pub(crate) fn new(
        builder: &'a mut TranscriptCommitmentBuilder,
        value: &'a Body,
        direction: Direction,
        built: &'a mut bool,
    ) -> Self {
        match value {
            Body::Json(body) => BodyCommitmentBuilder::Json(JsonCommitmentBuilder::new(
                builder, &body.0, direction, built,
            )),
            Body::Unknown(body) => BodyCommitmentBuilder::Unknown(UnknownCommitmentBuilder::new(
                builder, body, direction, built,
            )),
        }
    }

    /// Commits to the entire body.
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

    /// Builds the commitment to the body.
    pub fn build(self) -> Result<(), HttpCommitmentBuilderError> {
        match self {
            BodyCommitmentBuilder::Json(builder) => builder
                .build()
                .map_err(|e| HttpCommitmentBuilderError::Body(e.to_string())),
            BodyCommitmentBuilder::Unknown(builder) => builder
                .build()
                .map_err(|e| HttpCommitmentBuilderError::Body(e.to_string())),
        }
    }
}

/// Builder for proofs of an HTTP body.
#[derive(Debug)]
#[non_exhaustive]
pub enum BodyProofBuilder<'a, 'b> {
    /// Builder for proofs of a JSON body.
    Json(JsonProofBuilder<'a, 'b>),
    /// Builder for proofs of a body with an unknown format.
    Unknown(UnknownProofBuilder<'a, 'b>),
}

impl<'a, 'b> BodyProofBuilder<'a, 'b> {
    pub(crate) fn new(
        builder: &'a mut SubstringsProofBuilder<'b>,
        commitments: &'a TranscriptCommitments,
        value: &'a Body,
        direction: Direction,
        built: &'a mut bool,
    ) -> Self {
        match value {
            Body::Json(body) => BodyProofBuilder::Json(JsonProofBuilder::new(
                builder,
                commitments,
                &body.0,
                direction,
                built,
            )),
            Body::Unknown(body) => BodyProofBuilder::Unknown(UnknownProofBuilder::new(
                builder,
                commitments,
                body,
                direction,
                built,
            )),
        }
    }

    /// Proves the entire body.
    pub fn all(&mut self) -> Result<(), HttpProofBuilderError> {
        match self {
            BodyProofBuilder::Json(builder) => builder
                .all()
                .map_err(|e| HttpProofBuilderError::Body(e.to_string())),
            BodyProofBuilder::Unknown(builder) => builder
                .all()
                .map_err(|e| HttpProofBuilderError::Body(e.to_string())),
        }
    }

    /// Builds the proof for the body.
    pub fn build(self) -> Result<(), HttpProofBuilderError> {
        match self {
            BodyProofBuilder::Json(builder) => builder
                .build()
                .map_err(|e| HttpProofBuilderError::Body(e.to_string())),
            BodyProofBuilder::Unknown(builder) => builder
                .build()
                .map_err(|e| HttpProofBuilderError::Body(e.to_string())),
        }
    }
}
