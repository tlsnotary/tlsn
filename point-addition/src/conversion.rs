//! This module implements the conversion from the sum of two elliptic curve points to the sum of
//! two field elements of the field of the elliptic curve

use crate::{PointAddition, PointAdditionError, XCoordinateLabels};
use async_trait::async_trait;
use share_conversion_aio::{AdditiveToMultiplicative, MultiplicativeToAdditive};
use share_conversion_core::fields::Field;

pub struct Converter<T, U, V>
where
    T: AdditiveToMultiplicative<V>,
    U: MultiplicativeToAdditive<V>,
    V: Field,
{
    a2m_converter: T,
    m2a_converter: U,
}

impl<T, U> Converter {
    pub fn new(a2m_converter: T, m2a_converter: U) -> Self {
        Self(a2m_converter, m2a_converter)
    }
}

#[async_trait]
impl<T, U, V> PointAddition for Converter<T, U, V> {
    type Point = V;
    type XCoordinate = XCoordinateLabels;

    async fn compute_x_coordinate_share(
        &mut self,
        point: Self::Point,
    ) -> Result<Self::XCoordinate, PointAdditionError> {
        todo!()
    }
}
