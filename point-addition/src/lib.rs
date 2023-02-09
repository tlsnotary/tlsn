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
