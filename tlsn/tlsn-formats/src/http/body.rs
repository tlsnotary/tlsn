use tlsn_core::{
    commitment::{TranscriptCommitmentBuilder, TranscriptCommitments},
    proof::SubstringsProofBuilder,
    Direction,
};

use crate::{
    http::HttpCommitmentBuilderError,
    json::{JsonBody, JsonCommitmentBuilder, JsonProofBuilder},
    unknown::{UnknownCommitmentBuilder, UnknownProofBuilder, UnknownSpan},
};

use super::HttpProofBuilderError;

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

#[derive(Debug)]
#[non_exhaustive]
pub enum BodyProofBuilder<'a, 'b> {
    Json(JsonProofBuilder<'a, 'b>),
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
    pub fn build(&mut self) -> Result<(), HttpProofBuilderError> {
        match self {
            BodyProofBuilder::Json(builder) => builder
                .all()
                .map_err(|e| HttpProofBuilderError::Body(e.to_string())),
            BodyProofBuilder::Unknown(builder) => builder
                .all()
                .map_err(|e| HttpProofBuilderError::Body(e.to_string())),
        }
    }
}
