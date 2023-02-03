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
    a2m_converters: [T; 2],
    m2a_converters: [U; 2],
    negate: bool,
    _field: std::marker::PhantomData<V>,
}

impl<T, U, V> Converter<T, U, V>
where
    T: AdditiveToMultiplicative<V>,
    U: MultiplicativeToAdditive<V>,
    V: Field,
{
    pub fn new(a2m_converters: [T; 2], m2a_converters: [U; 2], negate: bool) -> Self {
        Self {
            a2m_converters,
            m2a_converters,
            negate,
            _field: std::marker::PhantomData,
        }
    }

    async fn convert(&mut self, point: [V; 2], run: usize) -> Result<V, PointAdditionError> {
        let point_neg = if self.negate {
            [-point[0], -point[1]]
        } else {
            point
        };

        let x = point_neg[0];
        let y = point_neg[1];

        let a = self.a2m_converters[run].a_to_m(vec![y]).await?[0];
        let b = self.a2m_converters[run].a_to_m(vec![x]).await?[0];

        let c = a * b.inverse();
        let c = c * c;

        let d = self.m2a_converters[run].m_to_a(vec![c]).await?[0];
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
    type Point = [V; 2];
    type XCoordinate = XCoordinateLabels;

    async fn compute_x_coordinate_share(
        &mut self,
        point: Self::Point,
    ) -> Result<Self::XCoordinate, PointAdditionError> {
        let (pms1, pms2) = (self.convert(point, 0).await?, self.convert(point, 1).await?);
        todo!()
    }
}
