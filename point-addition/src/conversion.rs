//! This module implements the conversion from the sum of two elliptic curve points to the sum of
//! two field elements of the field underlying the elliptic curve

use super::{PointAddition, PointAdditionError};
use async_trait::async_trait;
use mpc_core::Block;
use p256::EncodedPoint;
use share_conversion_aio::{AdditiveToMultiplicative, MultiplicativeToAdditive};
use share_conversion_core::fields::{p256::P256, Field};

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
    async fn convert(&mut self, [x, y]: [V; 2]) -> Result<V, PointAdditionError> {
        let [x_n, y_n] = if self.negate { [-x, -y] } else { [x, y] };

        let a = self.a2m_converter.a_to_m(vec![y_n]).await?[0];
        let b = self.a2m_converter.a_to_m(vec![x_n]).await?[0];

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

fn point_to_p256(point: EncodedPoint) -> Result<[P256; 2], PointAdditionError> {
    let x = point.x().ok_or(PointAdditionError::Coordinates)?;
    let y = point.y().ok_or(PointAdditionError::Coordinates)?;

    let x1 = <Block as From<[u8; 16]>>::from(
        x.as_slice()[..16]
            .try_into()
            .map_err(|_| PointAdditionError::Coordinates)?,
    );
    let x2 = <Block as From<[u8; 16]>>::from(
        x.as_slice()[16..]
            .try_into()
            .map_err(|_| PointAdditionError::Coordinates)?,
    );

    let y1 = <Block as From<[u8; 16]>>::from(
        y.as_slice()[..16]
            .try_into()
            .map_err(|_| PointAdditionError::Coordinates)?,
    );
    let y2 = <Block as From<[u8; 16]>>::from(
        y.as_slice()[16..]
            .try_into()
            .map_err(|_| PointAdditionError::Coordinates)?,
    );

    let x = P256::from([x1, x2]);
    let y = P256::from([y1, y2]);

    Ok([x, y])
}
