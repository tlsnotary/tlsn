use async_trait::async_trait;
use share_conversion_aio::ShareConversionError;

mod conversion;
#[cfg(feature = "mock")]
pub mod mock;

pub use conversion::Converter;

#[derive(Debug, thiserror::Error)]
pub enum PointAdditionError {
    #[error("ShareConversionError: {0}")]
    ShareConversion(#[from] ShareConversionError),
    #[error("Unable to get coordinates from elliptic curve point")]
    Coordinates,
}

/// This trait is for securely secret-sharing the addition of two elliptic curve points.
/// Let `P + Q = O = (x, y)`. Each party receives additive shares of the x-coordinate.
#[async_trait]
pub trait PointAddition {
    type Point;
    type XCoordinate;

    /// Adds two elliptic curve points in 2PC, returning respective secret shares
    /// of the resulting x-coordinate to both parties.
    async fn compute_x_coordinate_share(
        &mut self,
        point: Self::Point,
    ) -> Result<Self::XCoordinate, PointAdditionError>;
}

#[cfg(test)]
mod tests {
    use crate::{conversion::point_to_p256, PointAddition};

    use super::mock::create_mock_point_converter_pair;
    use p256::EncodedPoint;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha12Rng;

    #[tokio::test]
    async fn test_point_conversion() {
        let mut rng = ChaCha12Rng::from_seed([0_u8; 32]);
        let p1: [u8; 32] = rng.gen();
        let p2: [u8; 32] = rng.gen();
        let p1 = EncodedPoint::from_bytes(p1).unwrap();
        let p2 = EncodedPoint::from_bytes(p2).unwrap();
        let p = EncodedPoint::from_bytes(p2).unwrap();

        let (mut c1, mut c2) = create_mock_point_converter_pair();

        let c1_task = tokio::spawn(async move { c1.compute_x_coordinate_share(p1).await.unwrap() });
        let c2_task = tokio::spawn(async move { c2.compute_x_coordinate_share(p2).await.unwrap() });

        let (c1_output, c2_output) = tokio::join!(c1_task, c2_task);
        let (c1_output, c2_output) = (c1_output.unwrap(), c2_output.unwrap());

        assert_eq!(point_to_p256(p).unwrap()[0], c1_output + c2_output);
    }
}
