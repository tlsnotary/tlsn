//! This module implements the conversion from the sum of two elliptic curve points to the sum of
//! two field elements of the field underlying the elliptic curve

use super::{PointAddition, PointAdditionError};
use async_trait::async_trait;
use p256::{
    elliptic_curve::{AffinePoint, AffineXCoordinate},
    NistP256,
};
use share_conversion_aio::{AdditiveToMultiplicative, MultiplicativeToAdditive};
use share_conversion_core::fields::Field;

/// The instance used for converting the curve points
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
    /// A flag which is used to indicate the party, which has to do an inversion operation
    negate: bool,
    /// PhantomData used for the underlying elliptic curve field
    _field: std::marker::PhantomData<V>,
}

impl<T, U, V> Converter<T, U, V>
where
    T: AdditiveToMultiplicative<V>,
    U: MultiplicativeToAdditive<V>,
    V: Field,
{
    /// Create a new [Converter] instance
    pub fn new(a2m_converter: T, m2a_converter: U, negate: bool) -> Self {
        Self {
            a2m_converter,
            m2a_converter,
            negate,
            _field: std::marker::PhantomData,
        }
    }

    /// Perform the conversion of P = A + B => P_x = a + b
    ///
    /// This will convert an elliptic curve point addition to an additive sharing in the underlying
    /// field of the x-coordinate of that point
    async fn convert(&mut self, point: [V; 2]) -> Result<V, PointAdditionError> {
        let point_neg = if self.negate {
            [-point[0], -point[1]]
        } else {
            point
        };

        let x = point_neg[0];
        let y = point_neg[1];

        let a = self.a2m_converter.a_to_m(vec![y]).await?[0];
        let b = self.a2m_converter.a_to_m(vec![x]).await?[0];

        let c = a * b.inverse();
        let c = c * c;

        let d = self.m2a_converter.m_to_a(vec![c]).await?[0];
        let x_r = d + -point[0];

        Ok(x_r)
    }
}

#[async_trait]
impl<T, U, V> PointAddition for Converter<T, U, V>
where
    T: AdditiveToMultiplicative<V> + Send,
    U: MultiplicativeToAdditive<V> + Send,
    V: Field,
{
    type Point = AffinePoint<NistP256>;
    type XCoordinate = V;

    async fn compute_x_coordinate_share(
        &mut self,
        point: Self::Point,
    ) -> Result<Self::XCoordinate, PointAdditionError> {
        let (x, y) = (point.x(), point.y());
    }
}
