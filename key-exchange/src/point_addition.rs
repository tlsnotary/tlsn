use async_trait::async_trait;

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

pub mod mock {
    use super::*;

    use futures::{
        channel::oneshot::{channel, Sender},
        lock::Mutex,
    };
    use std::sync::Arc;

    use p256::{
        elliptic_curve::{AffineXCoordinate, Field, PrimeField},
        ProjectivePoint, Scalar,
    };

    struct Buffer {
        point: ProjectivePoint,
        channel: Sender<Scalar>,
    }

    #[derive(Clone)]
    pub struct MockP256PointAddition {
        buffer: Arc<Mutex<Option<Buffer>>>,
    }

    impl MockP256PointAddition {
        pub fn new() -> Self {
            Self {
                buffer: Arc::new(Mutex::new(None)),
            }
        }
    }

    #[async_trait]
    impl PointAddition for MockP256PointAddition {
        type Point = ProjectivePoint;
        type XCoordinate = Scalar;

        async fn share_x_coordinate(
            &mut self,
            point: Self::Point,
        ) -> Result<Self::XCoordinate, PointAdditionError> {
            let mut buffer = self.buffer.lock().await;

            // If buffer is already set, we compute the shares and send one of them over the channel.
            // Otherwise, we set the buffer and wait for the other party to send our share.
            if let Some(buffer) = buffer.take() {
                let shared_point = buffer.point + point;
                let x = shared_point.to_affine().x();

                let x = Scalar::from_repr(x).unwrap();
                let diff = Scalar::random(&mut rand::thread_rng());

                let x_0 = x.sub(&diff);
                let x_1 = diff;

                buffer.channel.send(x_0).unwrap();

                return Ok(x_1);
            } else {
                let (channel, receiver) = channel();
                *buffer = Some(Buffer { point, channel });
                drop(buffer);

                return Ok(receiver.await.unwrap());
            };
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        use p256::SecretKey;
        use rand::SeedableRng;

        #[tokio::test]
        async fn test_share_x_coordinate() {
            let mut leader = MockP256PointAddition::new();
            let mut follower = leader.clone();

            let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(0);

            let server_secret = SecretKey::random(&mut rng);
            let server_pk = server_secret.public_key();

            let leader_secret = SecretKey::random(&mut rng);

            let follower_secret = SecretKey::random(&mut rng);

            let leader_point = &server_pk.to_projective() * &leader_secret.to_nonzero_scalar();
            let follower_point = &server_pk.to_projective() * &follower_secret.to_nonzero_scalar();

            let shared_point = &leader_point + &follower_point;

            let expected_shared_x = Scalar::from_repr(shared_point.to_affine().x()).unwrap();

            let (leader_share, follower_share) = futures::join!(
                async { leader.share_x_coordinate(leader_point).await.unwrap() },
                async { follower.share_x_coordinate(follower_point).await.unwrap() }
            );

            let shared_x = leader_share.add(&follower_share);

            assert_eq!(shared_x, expected_shared_x);
        }
    }
}
