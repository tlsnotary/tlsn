//! This subcrate implements secure two-party (2PC) multiplication-to-addition (M2A) and
//! addition-to-multiplication (A2M) algorithms, both with semi-honest security.
//!
//! ### M2A algorithm
//! Let `A` be an element of some finite field with `A = a * b`, where `a` is only known to Alice
//! and `b` is only known to Bob. A is unknown to both parties and it is their goal that each of
//! them ends up with an additive share of A. So both parties start with `a` and `b` and want to
//! end up with `x` and `y`, where `A = a * b = x + y`.
//!
//! ### A2M algorithm
//! This is the other way round.
//! Let `A` be an element of some finite field with `A = x + y`, where `x` is only known to Alice
//! and `y` is only known to Bob. A is unknown to both parties and it is their goal that each of
//! them ends up with a multiplicative share of A. So both parties start with `x` and `y` and want to
//! end up with `a` and `b`, where `A = x + y = a * b`.

pub mod gf2_128;

use async_trait::async_trait;
use mpc_aio::protocol::ot::{OTError, OTFactoryError};
use thiserror::Error;

#[async_trait]
pub trait AdditiveToMultiplicative {
    type FieldElement: Copy + std::fmt::Debug;
    async fn a_to_m(
        &mut self,
        input: &[Self::FieldElement],
        id: String,
    ) -> Result<Vec<Self::FieldElement>, HomomorphicError>;
}

#[async_trait]
pub trait MultiplicativeToAdditive {
    type FieldElement: Copy + std::fmt::Debug;
    async fn m_to_a(
        &mut self,
        input: &[Self::FieldElement],
        id: String,
    ) -> Result<Vec<Self::FieldElement>, HomomorphicError>;
}

#[derive(Debug, Error)]
pub enum HomomorphicError {
    #[error("OTFactoryError: {0}")]
    OTFactoryError(#[from] OTFactoryError),
    #[error("OTError: {0}")]
    OTError(#[from] OTError),
}
