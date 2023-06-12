//! This module implements a secure two-party computation protocol for adding two private EC points
//! and secret-sharing the resulting x coordinate (the shares are field elements of the field
//! underlying the elliptic curve).
//! This protocol has semi-honest security.
//!
//! The protocol is described in <https://docs.tlsnotary.org/protocol/notarization/key_exchange.html>

use std::marker::PhantomData;

use super::{PointAddition, PointAdditionError};
use async_trait::async_trait;
use mpc_share_conversion::ShareConversion;
use mpc_share_conversion_core::fields::{p256::P256, Field};
use p256::EncodedPoint;

/// The instance used for adding the curve points
#[derive(Debug)]
pub struct MpcPointAddition<F, C>
where
    F: Field,
    C: ShareConversion<F>,
{
    /// Indicates which role this converter instance will fulfill
    role: Role,
    /// The share converter
    converter: C,

    _field: PhantomData<F>,
}

/// The role: either Leader or Follower
///
/// Follower needs to perform an inversion operation on the point during point addition
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy)]
pub enum Role {
    Leader,
    Follower,
}

impl Role {
    /// Adapt the point depending on the role
    ///
    /// One party needs to adapt the coordinates. We decided that this is the follower's job.
    fn adapt_point<V: Field>(&self, [x, y]: [V; 2]) -> [V; 2] {
        match self {
            Role::Leader => [x, y],
            Role::Follower => [-x, -y],
        }
    }
}

impl<F, C> MpcPointAddition<F, C>
where
    F: Field,
    C: ShareConversion<F> + std::fmt::Debug,
{
    /// Create a new [MpcPointAddition] instance
    #[cfg_attr(feature = "tracing", tracing::instrument(level = "info", ret))]
    pub fn new(role: Role, converter: C) -> Self {
        Self {
            converter,
            role,
            _field: PhantomData,
        }
    }

    /// Perform the conversion of P = A + B => P_x = a + b
    ///
    /// Since we are only interested in the x-coordinate of P (for the PMS) and because elliptic
    /// curve point addition is an expensive operation in 2PC, we secret-share the x-coordinate
    /// of P as a simple addition of field elements between the two parties. So we go from an EC
    /// point addition to an addition of field elements for the x-coordinate.
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "info", skip(point), err)
    )]
    async fn convert(&mut self, point: [F; 2]) -> Result<F, PointAdditionError> {
        let [x, y] = point;
        let [x_n, y_n] = self.role.adapt_point([x, y]);

        let a2m_output = self.converter.to_multiplicative(vec![y_n, x_n]).await?;

        let a = a2m_output[0];
        let b = a2m_output[1];

        let c = a * b.inverse();
        let c = c * c;

        let d = self.converter.to_additive(vec![c]).await?[0];
        let x_r = d + -x;

        Ok(x_r)
    }
}

#[async_trait]
impl<C> PointAddition for MpcPointAddition<P256, C>
where
    C: ShareConversion<P256> + Send + Sync + std::fmt::Debug,
{
    type Point = EncodedPoint;
    type XCoordinate = P256;

    async fn compute_x_coordinate_share(
        &mut self,
        point: Self::Point,
    ) -> Result<Self::XCoordinate, PointAdditionError> {
        let [x, y] = point_to_p256(point)?;
        self.convert([x, y]).await
    }
}

/// Convert the external library's point type to our library's field type
#[cfg_attr(
    feature = "tracing",
    tracing::instrument(level = "debug", skip(point), err)
)]
pub(crate) fn point_to_p256(point: EncodedPoint) -> Result<[P256; 2], PointAdditionError> {
    let x: [u8; 32] = (*point.x().ok_or(PointAdditionError::Coordinates)?).into();
    let y: [u8; 32] = (*point.y().ok_or(PointAdditionError::Coordinates)?).into();

    let x = P256::from(x);
    let y = P256::from(y);

    Ok([x, y])
}
