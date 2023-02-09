use super::{PointAddition, PointAdditionError};
use crate::conversion::{convert_p256, point_to_p256};
use async_trait::async_trait;
use mpc_core::Block;
use p256::EncodedPoint;
use share_conversion_aio::conversion::{
    mock::{mock_converter_pair, MockReceiver, MockSender},
    recorder::Void,
};
use share_conversion_core::{fields::p256::P256, AddShare, MulShare};

pub fn create_mock_point_converter_pair() -> (MockPointConversionSender, MockPointConversionReceiver)
{
    let (sender_a2m, receiver_a2m) =
        mock_converter_pair::<AddShare<P256>, P256, [Block; 2], Void>();
    let (sender_m2a, receiver_m2a) =
        mock_converter_pair::<MulShare<P256>, P256, [Block; 2], Void>();

    let sender = MockPointConversionSender {
        a2m_converter: sender_a2m,
        m2a_converter: sender_m2a,
        negate: true,
    };
    let receiver = MockPointConversionReceiver {
        a2m_converter: receiver_a2m,
        m2a_converter: receiver_m2a,
        negate: false,
    };

    (sender, receiver)
}

pub struct MockPointConversionSender {
    a2m_converter: MockSender<AddShare<P256>, P256, [Block; 2], Void>,
    m2a_converter: MockSender<MulShare<P256>, P256, [Block; 2], Void>,
    negate: bool,
}

impl MockPointConversionSender {
    async fn convert(&mut self, [x, y]: [P256; 2]) -> Result<P256, PointAdditionError> {
        convert_p256(
            &mut self.a2m_converter,
            &mut self.m2a_converter,
            self.negate,
            [x, y],
        )
        .await
    }
}

pub struct MockPointConversionReceiver {
    a2m_converter: MockReceiver<AddShare<P256>, P256, [Block; 2], Void>,
    m2a_converter: MockReceiver<MulShare<P256>, P256, [Block; 2], Void>,
    negate: bool,
}

impl MockPointConversionReceiver {
    async fn convert(&mut self, [x, y]: [P256; 2]) -> Result<P256, PointAdditionError> {
        convert_p256(
            &mut self.a2m_converter,
            &mut self.m2a_converter,
            self.negate,
            [x, y],
        )
        .await
    }
}

#[async_trait]
impl PointAddition for MockPointConversionSender {
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

#[async_trait]
impl PointAddition for MockPointConversionReceiver {
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
