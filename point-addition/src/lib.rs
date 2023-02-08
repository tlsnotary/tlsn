use async_trait::async_trait;
use mpc_core::garble::{ActiveLabels, FullLabels};
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

/// Encoded shares of the x-coordinate of the shared point.
#[derive(Debug, Clone)]
pub struct XCoordinateLabels {
    pub full_share_a_labels: FullLabels,
    pub full_share_b_labels: FullLabels,
    pub active_share_a_labels: ActiveLabels,
    pub active_share_b_labels: ActiveLabels,
}

impl XCoordinateLabels {
    pub fn new(
        full_share_a_labels: FullLabels,
        full_share_b_labels: FullLabels,
        active_share_a_labels: ActiveLabels,
        active_share_b_labels: ActiveLabels,
    ) -> Self {
        Self {
            full_share_a_labels,
            full_share_b_labels,
            active_share_a_labels,
            active_share_b_labels,
        }
    }

    pub fn full_share_a_labels(&self) -> &FullLabels {
        &self.full_share_a_labels
    }

    pub fn full_share_b_labels(&self) -> &FullLabels {
        &self.full_share_b_labels
    }

    pub fn active_share_a_labels(&self) -> &ActiveLabels {
        &self.active_share_a_labels
    }

    pub fn active_share_b_labels(&self) -> &ActiveLabels {
        &self.active_share_b_labels
    }
}
