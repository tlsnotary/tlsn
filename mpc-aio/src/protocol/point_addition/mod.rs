pub use mpc_core::point_addition::P256SecretShare;

use mpc_core::point_addition::PointAdditionError as CoreError;

#[derive(Debug, thiserror::Error)]
pub enum PointAdditionError {
    #[error("Secret share failed due to io error: {0}")]
    IOError(#[from] std::io::Error),
    #[error("Encountered core error: {0:?}")]
    CoreError(#[from] CoreError),
}

use async_trait::async_trait;
use mockall::automock;

/// This trait is for securely secret-sharing the addition of two elliptic curve points.
/// Let `P + Q = O = (x, y)`. Each party receives additive shares of the x-coordinate where `x_m + x_s = x`.
#[automock]
#[async_trait]
pub trait PointAddition2PC {
    async fn add(
        &mut self,
        point: &p256::EncodedPoint,
    ) -> Result<P256SecretShare, PointAdditionError>;
}
