pub mod mock;

use async_trait::async_trait;

use tls_core::key::PublicKey;

#[derive(Debug, thiserror::Error)]
pub enum KeyExchangeError {
    #[error("PointAdditionError: {0}")]
    PointAdditionError(#[from] PointAdditionError),
}

#[async_trait]
pub trait KeyExchange {
    /// Sets the public key share.
    async fn set_key_share(&mut self, key: PublicKey) -> Result<(), KeyExchangeError>;
    /// Returns the client's public key share.
    async fn get_client_key_share(&mut self) -> Result<PublicKey, KeyExchangeError>;
    /// Sets the server's public key share.
    async fn set_server_key_share(&mut self, key: PublicKey) -> Result<(), KeyExchangeError>;
    /// Computes the pms share.
    async fn get_pms_share(&mut self) -> Result<Vec<u8>, KeyExchangeError>;
}

#[derive(Debug, thiserror::Error)]
pub enum PointAdditionError {}

/// This trait is for securely secret-sharing the addition of two elliptic curve points.
/// Let `P + Q = O = (x, y)`. Each party receives additive shares of the x-coordinate.
#[async_trait]
pub trait PointAddition {
    type Point;
    type XCoordinate;

    /// Adds two elliptic curve points in 2PC, returning respective secret shares
    /// of the resulting x-coordinate to both parties.
    async fn share_x_coordinate(
        &mut self,
        point: Self::Point,
    ) -> Result<Self::XCoordinate, PointAdditionError>;
}
