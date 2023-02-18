//! This module implements a secure two-party computation protocol for adding two private EC points
//! and secret-sharing the resulting x coordinate (the shares are field elements of the field
//! underlying the elliptic curve).
//! This protocol has semi-honest security.
//!
//! The protocol is described in <https://docs.tlsnotary.org/protocol/notarization/key_exchange.html>

use super::{PointAddition, PointAdditionError};
use async_trait::async_trait;
use p256::EncodedPoint;
use share_conversion_aio::{AdditiveToMultiplicative, MultiplicativeToAdditive};
use share_conversion_core::fields::{p256::P256, Field};

/// The instance used for adding the curve points
pub struct Converter<T, U, V>
where
    T: AdditiveToMultiplicative<V>,
    U: MultiplicativeToAdditive<V>,
    V: Field,
{
    /// Performs conversion of addition to multiplication
    a2m_converter: T,
    /// Performs conversion of multiplication to addition
    m2a_converter: U,
    /// Indicates which role this converter instance will fulfill
    role: Role,
    /// PhantomData used for the underlying elliptic curve field
    _field: std::marker::PhantomData<V>,
}

/// The role: either Leader or Follower
///
/// Follower needs to perform an inversion operation on the point during point addition
#[derive(Debug, Clone, Copy)]
pub enum Role {
    Leader,
    Follower,
}

impl Role {
    fn adapt_point<V: Field>(&self, [x, y]: [V; 2]) -> [V; 2] {
        match self {
            Role::Leader => [x, y],
            Role::Follower => [-x, -y],
        }
    }
}

impl<T, U, V> Converter<T, U, V>
where
    T: AdditiveToMultiplicative<V>,
    U: MultiplicativeToAdditive<V>,
    V: Field,
{
    /// Create a new [Converter] instance
    pub fn new(a2m_converter: T, m2a_converter: U, role: Role) -> Self {
        Self {
            a2m_converter,
            m2a_converter,
            role,
            _field: std::marker::PhantomData,
        }
    }

    /// Perform the conversion of P = A + B => P_x = a + b
    ///
    /// Since we are only interested in the x-coordinate of P (for the PMS) and because elliptic
    /// curve point addition is an expensive operation in 2PC, we secretly share the x-coordinate
    /// of P as a simple addition of field elements between the two parties. So we go from an EC
    /// point addition to an addition of field elements for the x-coordinate.
    async fn convert(&mut self, [x, y]: [V; 2]) -> Result<V, PointAdditionError> {
        let [x_n, y_n] = self.role.adapt_point([x, y]);

        let a2m_output = self.a2m_converter.a_to_m(vec![y_n, x_n]).await?;

        let a = a2m_output[0];
        let b = a2m_output[1];

        let c = a * b.inverse();
        let c = c * c;

        let d = self.m2a_converter.m_to_a(vec![c]).await?[0];
        let x_r = d + -x;

        Ok(x_r)
    }
}

#[async_trait]
impl<T, U> PointAddition for Converter<T, U, P256>
where
    T: AdditiveToMultiplicative<P256> + Send,
    U: MultiplicativeToAdditive<P256> + Send,
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

pub(crate) fn point_to_p256(point: EncodedPoint) -> Result<[P256; 2], PointAdditionError> {
    let x: [u8; 32] = (*point.x().ok_or(PointAdditionError::Coordinates)?).into();
    let y: [u8; 32] = (*point.y().ok_or(PointAdditionError::Coordinates)?).into();

    let x = P256::from(x);
    let y = P256::from(y);

    Ok([x, y])
}
